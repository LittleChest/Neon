use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

pub(crate) const BYPASS_MARK: u32 = 0x20000;

const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const ICMP_PROBE_TIMEOUT_SECS: u64 = 5;
const RECV_TIMEOUT_MS: u64 = 500;
const INTERNET_CHECK_TIMEOUT_SECS: u64 = 1;

const IPV4_VERSION_IHL: u8 = 0x45;
const IPV4_HEADER_SIZE: usize = 20;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_HEADER_SIZE: usize = 64;
const ICMP_DATA_SIZE: usize = 56;
const IP_ICMP_PROTOCOL: u8 = 1;

const PROBE_BUFFER_SIZE: usize = 2048;
const DNS_SERVER: &str = "1.1.1.1";
const PROBE_IDENT: u16 = 0x4E4F;
const PROBE_SEQ: u16 = 1;
const HANDSHAKE_RESPONSE_SIZE: usize = 92;
const HANDSHAKE_RESPONSE_TYPE: u8 = 2;

#[derive(Debug)]
pub struct ProbeOutcome {
    pub endpoint: SocketAddr,
    pub rtt: Duration,
}

/// WireGuard连接跳跃引擎
/// 用于在多个端点中探测和选择最佳连接
pub struct HoppingEngine {
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
}

impl HoppingEngine {
    /// 创建新的跳跃引擎实例
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            private_key: StaticSecret::from(private_key),
            peer_public_key: PublicKey::from(peer_public_key),
            preshared_key,
        }
    }

    pub async fn race_for_first(
        &self,
        endpoints: &[SocketAddr],
        count: usize,
    ) -> Option<SocketAddr> {
        let candidates = random_sample(endpoints, count);
        let mut probes = FuturesUnordered::new();
        
        for ep in candidates {
            probes.push(self.probe(ep));
        }

        while let Some(outcome) = probes.next().await {
            if let Some(o) = outcome {
                return Some(o.endpoint);
            }
        }
        
        None
    }

    pub async fn find_lowest_latency(
        &self,
        endpoints: &[SocketAddr],
        count: usize,
    ) -> Option<SocketAddr> {
        let candidates = random_sample(endpoints, count);
        let mut probes = FuturesUnordered::new();
        
        for ep in candidates {
            probes.push(self.probe(ep));
        }

        let mut results = Vec::new();
        while let Some(outcome) = probes.next().await {
            if let Some(o) = outcome {
                results.push(o);
            }
        }

        if results.is_empty() {
            return None;
        }

        results.sort_by_key(|o| o.rtt);
        
        let best = results[0].endpoint;
        println!("ℹ️ 本轮测速 {} 个节点，最优延迟: {:.0}ms -> {}", 
                 results.len(), results[0].rtt.as_secs_f64() * 1000.0, best);

        Some(best)
    }

    pub async fn check_connectivity(&self) -> bool {
        check_internet_raw().await
    }

    pub async fn probe(&self, endpoint: SocketAddr) -> Option<ProbeOutcome> {
        let mut tunnel = Tunn::new(
            self.private_key.clone(),
            self.peer_public_key,
            self.preshared_key,
            None,
            0,
            None,
        );

        let bind_addr = if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = {
            let std_socket = std::net::UdpSocket::bind(bind_addr).ok()?;
            set_fwmark(&std_socket, BYPASS_MARK);
            std_socket.connect(endpoint).ok()?;
            std_socket.set_nonblocking(true).ok()?;
            UdpSocket::from_std(std_socket).ok()?
        };

        let t0 = Instant::now();

        let hs_deadline = Instant::now() + Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
        let mut tx = [0u8; PROBE_BUFFER_SIZE];
        let mut rx = [0u8; PROBE_BUFFER_SIZE];

        let init_pkt = match tunnel.format_handshake_initiation(&mut tx, true) {
            TunnResult::WriteToNetwork(pkt) => pkt,
            _ => return None,
        };
        if socket.send(init_pkt).await.is_err() {
            return None;
        }

        loop {
            if Instant::now() >= hs_deadline {
                return None;
            }
            let remaining = hs_deadline.saturating_duration_since(Instant::now());
            let recv_timeout = remaining.min(Duration::from_millis(RECV_TIMEOUT_MS));
            match tokio::time::timeout(recv_timeout, socket.recv(&mut rx)).await {
                Ok(Ok(size)) => {
                    match tunnel.decapsulate(None, &rx[..size], &mut tx) {
                        TunnResult::WriteToNetwork(pkt) => {
                            let _ = socket.send(pkt).await;
                            if size == HANDSHAKE_RESPONSE_SIZE && rx[0] == HANDSHAKE_RESPONSE_TYPE {
                                break;
                            }
                        }
                        TunnResult::Done => {
                            if size == HANDSHAKE_RESPONSE_SIZE && rx[0] == HANDSHAKE_RESPONSE_TYPE {
                                break;
                            }
                        }
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(Err(_)) => return None,
                Err(_) => {
                    if let TunnResult::WriteToNetwork(pkt) = tunnel.update_timers(&mut tx) {
                        let _ = socket.send(pkt).await;
                    }
                }
            }
        }

        let icmp_deadline = Instant::now() + Duration::from_secs(ICMP_PROBE_TIMEOUT_SECS);

        let local_ip = match socket.local_addr() {
            Ok(addr) => match addr {
                SocketAddr::V4(a) => *a.ip(),
                _ => return None,
            },
            Err(_) => return None,
        };
        let dst_ip = DNS_SERVER.parse::<std::net::Ipv4Addr>().unwrap();

        let mut plain_pkt = [0u8; 256];
        let mut enc_pkt = [0u8; 256];
        let pkt_len = build_echo_request(local_ip, dst_ip, 64, PROBE_SEQ, PROBE_IDENT, &mut plain_pkt);

        match tunnel.encapsulate(&plain_pkt[..pkt_len], &mut enc_pkt) {
            TunnResult::WriteToNetwork(pkt) => {
                if socket.send(pkt).await.is_err() {
                    return None;
                }
            }
            _ => return None,
        }

        loop {
            if Instant::now() >= icmp_deadline {
                return None;
            }
            let remaining = icmp_deadline.saturating_duration_since(Instant::now());
            let recv_timeout = remaining.min(Duration::from_millis(RECV_TIMEOUT_MS));
            match tokio::time::timeout(recv_timeout, socket.recv(&mut rx)).await {
                Ok(Ok(size)) => {
                    match tunnel.decapsulate(None, &rx[..size], &mut tx) {
                        TunnResult::WriteToTunnelV4(pkt, _) => {
                            if let Some((r_ident, r_seq)) = parse_icmp_reply(pkt) {
                                if r_ident == PROBE_IDENT && r_seq == PROBE_SEQ {
                                    let rtt = t0.elapsed();
                                    return Some(ProbeOutcome { endpoint, rtt });
                                }
                            }
                        }
                        TunnResult::WriteToNetwork(pkt) => {
                            let _ = socket.send(pkt).await;
                        }
                        _ => {}
                    }
                }
                Ok(Err(_)) => return None,
                Err(_) => {
                    match tunnel.encapsulate(&plain_pkt[..pkt_len], &mut enc_pkt) {
                        TunnResult::WriteToNetwork(pkt) => {
                            let _ = socket.send(pkt).await;
                        }
                        _ => {}
                    }
                    if let TunnResult::WriteToNetwork(pkt) = tunnel.update_timers(&mut tx) {
                        let _ = socket.send(pkt).await;
                    }
                }
            }
        }
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo_request(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    ttl: u8,
    seq: u16,
    ident: u16,
    out: &mut [u8],
) -> usize {
    // ICMP header (20..84)
    let icmp = &mut out[IPV4_HEADER_SIZE..IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
    icmp[0] = ICMP_ECHO_REQUEST;
    icmp[1] = 0;
    icmp[2..4].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    for i in 0..ICMP_DATA_SIZE {
        icmp[8 + i] = i as u8;
    }
    let icmp_cksum = calculate_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_cksum.to_be_bytes());

    // IPv4 header (0..20)
    out[0] = IPV4_VERSION_IHL;
    out[1] = 0;
    let total_len = (IPV4_HEADER_SIZE + ICMP_HEADER_SIZE) as u16;
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8] = ttl;
    out[9] = IP_ICMP_PROTOCOL;
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_cksum = calculate_checksum(&out[..IPV4_HEADER_SIZE]);
    out[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    IPV4_HEADER_SIZE + ICMP_HEADER_SIZE
}

fn parse_icmp_reply(pkt: &[u8]) -> Option<(u16, u16)> {
    if pkt.len() < 28 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    // ICMP type 0 = Echo Reply
    if pkt[ihl] != ICMP_ECHO_REPLY {
        return None;
    }
    let ident = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
    let seq = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
    Some((ident, seq))
}

pub fn decode_b64_key(b64: &str) -> Result<[u8; 32], String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut buf = [0u8; 64];
    let len = STANDARD
        .decode_slice(b64.trim(), &mut buf)
        .map_err(|e| format!("无效的密钥: {e}"))?;
    if len != 32 {
        return Err(format!("密钥长度应为 32 字节，但实际是 {len} 字节"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[..32]);
    Ok(key)
}

pub fn random_sample<T: Copy>(items: &[T], n: usize) -> Vec<T> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let len = items.len();
    let n = n.min(len);
    let mut indices: Vec<usize> = (0..len).collect();

    let seed = RandomState::new().build_hasher().finish();
    let mut r = seed;
    for i in 0..n {
        r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = i + (r as usize) % (len - i);
        indices.swap(i, j);
    }

    indices[..n].iter().map(|&i| items[i]).collect()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_fwmark(socket: &std::net::UdpSocket, mark: u32) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        );
    }
}

pub async fn run_test(engine: &HoppingEngine, ports: &[u16], ip_range: &[u8; 4], ip_count: u8) {
    use std::net::{Ipv4Addr, SocketAddrV4};

    let total = ports.len();
    println!("正在 8 线程测试 {total} 个端点");

    let endpoints: Vec<SocketAddr> = ports
        .iter()
        .enumerate()
        .map(|(i, &port)| {
            let ip_idx = (i as u8) % ip_count;
            let ip = Ipv4Addr::new(ip_range[0], ip_range[1], ip_range[2], ip_range[3] + ip_idx);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        })
        .collect();

    let mut success = 0u32;
    let mut failed = 0u32;
    let mut results: Vec<(SocketAddr, std::time::Duration)> = Vec::with_capacity(total);

    for chunk in endpoints.chunks(8) {
        let mut probes = FuturesUnordered::new();
        for &ep in chunk {
            probes.push(async move { (ep, engine.probe(ep).await) });
        }
        while let Some((ep, outcome)) = probes.next().await {
            match outcome {
                Some(o) => {
                    println!("  ✅ {}  {:.0}ms", ep, o.rtt.as_secs_f64() * 1000.0);
                    results.push((ep, o.rtt));
                    success += 1;
                }
                None => {
                    println!("  ❌ {ep}  超时");
                    failed += 1;
                }
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }

    println!("\n完成: {success} 可达, {failed} 超时");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    results.sort_by_key(|(_, rtt)| *rtt);
    let top5: Vec<_> = results.iter().take(5).collect();
    if !top5.is_empty() {
        println!("\n最快 5 个:");
        for (i, (ep, rtt)) in top5.iter().enumerate() {
            println!("  {}. {}  {:.0}ms", i + 1, ep, rtt.as_secs_f64() * 1000.0);
        }
    }
}

async fn check_internet_raw() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddrV4;

    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if socket.set_nonblocking(true).is_err() {
        return false;
    }

    let dst = SocketAddrV4::new(DNS_SERVER.parse::<std::net::Ipv4Addr>().unwrap(), 0);
    let mut pkt = [0u8; 8];
    pkt[0] = ICMP_ECHO_REQUEST;
    pkt[1] = 0; // Code: 0
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // Identifier
    pkt[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // Sequence number

    let cksum = calculate_checksum(&pkt[..8]);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

    let std_sock: std::net::UdpSocket = socket.into();
    let sock_tokio = match UdpSocket::from_std(std_sock) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if sock_tokio.send_to(&pkt[..8], std::net::SocketAddr::V4(dst)).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 1024];
    let timeout = Duration::from_secs(INTERNET_CHECK_TIMEOUT_SECS);
    match tokio::time::timeout(timeout, sock_tokio.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            if n >= 28 {
                let ihl = (buf[0] & 0x0f) as usize * 4;
                if n >= ihl + 8 && buf[ihl] == ICMP_ECHO_REPLY {
                    let r_ident = u16::from_be_bytes([buf[ihl + 4], buf[ihl + 5]]);
                    let r_seq = u16::from_be_bytes([buf[ihl + 6], buf[ihl + 7]]);
                    if r_ident == 0x1234 && r_seq == 0x0001 {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}
