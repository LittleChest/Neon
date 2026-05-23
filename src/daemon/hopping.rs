use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

pub(crate) const BYPASS_MARK: u32 = 0x114514;

#[derive(Debug)]
pub struct ProbeOutcome {
    pub endpoint: SocketAddr,
    pub rtt: Duration,
}

pub struct HoppingEngine {
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
}

impl HoppingEngine {
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

    pub async fn find_best(
        &self,
        endpoints: &[SocketAddr],
        concurrent: usize,
        wait_sec: u64,
    ) -> Option<SocketAddr> {
        let count = if concurrent == 0 { 1 } else { concurrent };
        if endpoints.is_empty() {
            return None;
        }

        loop {
            let candidates = random_sample(endpoints, count);
            let mut probes = FuturesUnordered::new();
            for ep in candidates {
                probes.push(self.probe(ep));
            }
            while let Some(outcome) = probes.next().await {
                match outcome {
                    Some(o) => {
                        println!(
                            "使用端点: {} (RTT {:.0}ms)",
                            o.endpoint,
                            o.rtt.as_secs_f64() * 1000.0
                        );
                        return Some(o.endpoint);
                    }
                    None => continue,
                }
            }
            println!("等待 {wait_sec} 秒后重试...");
            tokio::time::sleep(Duration::from_secs(wait_sec)).await;
        }
    }

    pub async fn pick_initial(&self, endpoints: &[SocketAddr], max_probes: usize) -> Option<SocketAddr> {
        if endpoints.is_empty() {
            return None;
        }
        let count = if max_probes == 0 { 1 } else { max_probes };

        let candidates = random_sample(endpoints, count);
        let mut probes = FuturesUnordered::new();
        for ep in candidates {
            probes.push(self.probe(ep));
        }

        let mut working: Vec<SocketAddr> = Vec::new();
        while let Some(outcome) = probes.next().await {
            if let Some(o) = outcome {
                working.push(o.endpoint);
            }
        }

        if working.is_empty() {
            let fallback = random_sample(endpoints, 1)[0];
            println!("未找到可用端点，使用: {fallback}");
            Some(fallback)
        } else {
            let pick = random_sample(&working, 1)[0];
            println!("从 {} 个可用端点中选择: {pick}", working.len());
            Some(pick)
        }
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
            UdpSocket::from_std(std_socket).ok()?
        };

        let t0 = Instant::now();

        let hs_deadline = Instant::now() + Duration::from_secs(5);
        let mut tx = [0u8; 2048];
        let mut rx = [0u8; 2048];

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
            let recv_timeout = remaining.min(Duration::from_millis(500));
            match tokio::time::timeout(recv_timeout, socket.recv(&mut rx)).await {
                Ok(Ok(size)) => {
                    match tunnel.decapsulate(None, &rx[..size], &mut tx) {
                        TunnResult::WriteToNetwork(pkt) => {
                            let _ = socket.send(pkt).await;
                            if size == 92 && rx[0] == 2 {
                                break;
                            }
                        }
                        TunnResult::Done => {
                            if size == 92 && rx[0] == 2 {
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

        let icmp_deadline = Instant::now() + Duration::from_secs(5);

        let local_ip = match socket.local_addr() {
            Ok(addr) => match addr {
                SocketAddr::V4(a) => *a.ip(),
                _ => return None,
            },
            Err(_) => return None,
        };
        let dst_ip = std::net::Ipv4Addr::new(1, 1, 1, 1);

        let mut plain_pkt = [0u8; 256];
        let mut enc_pkt = [0u8; 256];
        let ident = 0x4E4F_u16;
        let seq = 1u16;
        let pkt_len = build_echo_request(local_ip, dst_ip, 64, seq, ident, &mut plain_pkt);

        match tunnel.encapsulate(&plain_pkt[..pkt_len], &mut enc_pkt) {
            TunnResult::WriteToNetwork(pkt) => {
                if socket.send(pkt).await.is_err() {
                    return None;
                }
            }
            _ => return None,
        }

        // 等待 ICMP echo reply（带重试）
        loop {
            if Instant::now() >= icmp_deadline {
                return None;
            }
            let remaining = icmp_deadline.saturating_duration_since(Instant::now());
            let recv_timeout = remaining.min(Duration::from_millis(500));
            match tokio::time::timeout(recv_timeout, socket.recv(&mut rx)).await {
                Ok(Ok(size)) => {
                    match tunnel.decapsulate(None, &rx[..size], &mut tx) {
                        TunnResult::WriteToTunnelV4(pkt, _) => {
                            if let Some((r_ident, r_seq)) = parse_icmp_reply(pkt) {
                                if r_ident == ident && r_seq == seq {
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
    let icmp = &mut out[20..84];
    icmp[0] = 8; // Echo Request
    icmp[1] = 0;
    icmp[2..4].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    for i in 0..56 {
        icmp[8 + i] = i as u8;
    }
    let icmp_cksum = calculate_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_cksum.to_be_bytes());

    // IPv4 header (0..20)
    out[0] = 0x45; // version + IHL
    out[1] = 0;
    out[2..4].copy_from_slice(&84u16.to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8] = ttl;
    out[9] = 1; // ICMP protocol
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_cksum = calculate_checksum(&out[..20]);
    out[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    84
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
    if pkt[ihl] != 0 {
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

fn random_sample<T: Copy>(items: &[T], n: usize) -> Vec<T> {
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
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::net::{Ipv4Addr, SocketAddrV4};

    let total = ports.len();
    println!("正在 8 线程测试 {total} 个端点");

    let seed = RandomState::new().build_hasher().finish();
    let endpoints: Vec<SocketAddr> = ports
        .iter()
        .enumerate()
        .map(|(i, &port)| {
            let r = seed.wrapping_mul(i as u64 + 1).wrapping_add(1442695040888963407);
            let ip_idx = (r as u8) % ip_count;
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
