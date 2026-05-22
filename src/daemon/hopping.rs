use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

#[derive(Debug)]
struct ProbeOutcome {
    endpoint: SocketAddr,
    rtt: Duration,
}

pub struct HoppingEngine {
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    probe_timeout: Duration,
}

impl HoppingEngine {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            private_key: StaticSecret::from(private_key),
            peer_public_key: PublicKey::from(peer_public_key),
            preshared_key,
            probe_timeout,
        }
    }

    pub async fn find_best(
        &self,
        endpoints: &[SocketAddr],
        concurrent: usize,
    ) -> Option<SocketAddr> {
        let count = if concurrent == 0 { 1 } else { concurrent };
        let candidates: Vec<_> = endpoints.iter().take(count).copied().collect();

        if candidates.is_empty() {
            return None;
        }

        let mut probes = FuturesUnordered::new();
        for ep in candidates {
            probes.push(self.probe_one(ep));
        }

        while let Some(outcome) = probes.next().await {
            match outcome {
                Some(o) => {
                    crate::state::logger::Logger::info(&format!(
                        "计划使用端点: {} (RTT {:.0}ms)",
                        o.endpoint,
                        o.rtt.as_secs_f64() * 1000.0
                    ));
                    return Some(o.endpoint);
                }
                None => continue,
            }
        }

        crate::state::logger::Logger::warn("未找到可用端点");
        None
    }

    async fn probe_one(&self, endpoint: SocketAddr) -> Option<ProbeOutcome> {
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

        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        socket.connect(endpoint).await.ok()?;

        let t0 = Instant::now();
        let result = timeout(self.probe_timeout, do_handshake(&mut tunnel, &socket)).await;

        match result {
            Ok(true) => {
                let rtt = t0.elapsed();
                Some(ProbeOutcome { endpoint, rtt })
            }
            _ => None,
        }
    }
}

async fn do_handshake(tunnel: &mut Tunn, socket: &UdpSocket) -> bool {
    let mut tx = [0u8; 2048];
    let mut rx = [0u8; 2048];

    match tunnel.format_handshake_initiation(&mut tx, true) {
        TunnResult::WriteToNetwork(pkt) => {
            if socket.send(pkt).await.is_err() {
                return false;
            }
        }
        _ => return false,
    }

    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        if Instant::now() > deadline {
            return false;
        }

        let read_timeout = Duration::from_millis(200);

        match timeout(read_timeout, socket.recv(&mut rx)).await {
            Ok(Ok(size)) => {
                match tunnel.decapsulate(None, &rx[..size], &mut tx) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let _ = socket.send(pkt).await;
                        if size == 92 && rx[0] == 2 {
                            return true;
                        }
                    }
                    TunnResult::Done => {
                        if size == 92 && rx[0] == 2 {
                            return true;
                        }
                    }
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        return true;
                    }
                    _ => {}
                }
            }
            Ok(Err(_)) => return false,
            Err(_) => {
                if let TunnResult::WriteToNetwork(pkt) = tunnel.update_timers(&mut tx) {
                    let _ = socket.send(pkt).await;
                }
            }
        }
    }
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

