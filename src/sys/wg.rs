use crate::state::logger::Logger;
use std::io;
use std::net::SocketAddr;
use std::time::SystemTime;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub struct WgManager;

impl WgManager {
    pub async fn check_kernel_support() -> io::Result<()> {
        tokio::task::spawn_blocking(|| {
            Device::list(Backend::Kernel).map(|_| ()).map_err(|e| {
                Logger::fatal("此内核不支持 WireGuard");
                io::Error::new(io::ErrorKind::Other, e)
            })
        })
        .await
        .unwrap()
    }

    pub async fn find_available_name() -> io::Result<InterfaceName> {
        tokio::task::spawn_blocking(|| {
            for i in 0..100 {
                let name = if i == 0 {
                    "warp".to_string()
                } else {
                    format!("warp{}", i - 1)
                };

                let iface: InterfaceName = name.parse().map_err(|e| {
                    Logger::error(&format!("无效的接口名 {name}: {e}"));
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;

                match Device::get(&iface, Backend::Kernel) {
                    Ok(_) => continue,
                    Err(e) if e.kind() == io::ErrorKind::NotFound
                           || e.raw_os_error() == Some(19) =>
                    {
                        Logger::info(&format!("已选择接口: {name}"));
                        return Ok(iface);
                    }
                    Err(e) => {
                        Logger::error(&format!("查询接口 {name} 失败: {e}"));
                        return Err(e);
                    }
                }
            }

            Logger::fatal("未找到可用接口名");
            Err(io::Error::new(io::ErrorKind::AlreadyExists, "warp0..99 已满"))
        })
        .await
        .unwrap()
    }

    pub async fn apply_device_config(
        iface: InterfaceName,
        private_key: String,
        fwmark: u32,
        listen_port: Option<u16>,
    ) -> io::Result<()> {
        tokio::task::spawn_blocking(move || {
            let key = Key::from_base64(&private_key).map_err(|_| {
                Logger::fatal("无效的私钥格式");
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid private key")
            })?;

            let mut update = DeviceUpdate::new()
                .set_private_key(key)
                .set_fwmark(fwmark);

            update = match listen_port {
                Some(port) => update.set_listen_port(port),
                None => update.randomize_listen_port(),
            };

            update.apply(&iface, Backend::Kernel).map_err(|e| {
                Logger::fatal(&format!("无法应用 WireGuard 配置: {e}"));
                io::Error::new(io::ErrorKind::Other, e)
            })?;

            Logger::info("已应用 WireGuard 配置");
            Ok(())
        })
        .await
        .unwrap()
    }

    pub async fn set_peer(
        iface: InterfaceName,
        peer_key: String,
        endpoint: SocketAddr,
        keepalive: u16,
    ) -> io::Result<()> {
        tokio::task::spawn_blocking(move || {
            let key = Key::from_base64(&peer_key).map_err(|_| {
                Logger::fatal("无效的对端公钥");
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid peer key")
            })?;

            let peer = PeerConfigBuilder::new(&key)
                .set_endpoint(endpoint)
                .set_persistent_keepalive_interval(keepalive)
                .replace_allowed_ips()
                .allow_all_ips();

            DeviceUpdate::new()
                .replace_peers()
                .add_peer(peer)
                .apply(&iface, Backend::Kernel)
                .map_err(|e| {
                    Logger::fatal(&format!("无法设置对端: {e}"));
                    io::Error::new(io::ErrorKind::Other, e)
                })?;

            Logger::info(&format!("已使用端点: {endpoint} 添加对端"));
            Ok(())
        })
        .await
        .unwrap()
    }

    pub async fn update_endpoint(
        iface: InterfaceName,
        peer_key: String,
        endpoint: SocketAddr,
    ) -> io::Result<()> {
        tokio::task::spawn_blocking(move || {
            let key = Key::from_base64(&peer_key).map_err(|_| {
                Logger::error("无效的对端公钥");
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid peer key")
            })?;

            let peer = PeerConfigBuilder::new(&key).set_endpoint(endpoint);

            DeviceUpdate::new()
                .add_peer(peer)
                .apply(&iface, Backend::Kernel)
                .map_err(|e| {
                    Logger::error(&format!("无法更新端点: {e}"));
                    io::Error::new(io::ErrorKind::Other, e)
                })?;

            Ok(())
        })
        .await
        .unwrap()
    }

    pub async fn get_stats(iface: InterfaceName) -> io::Result<DeviceStats> {
        tokio::task::spawn_blocking(move || {
            let device = Device::get(&iface, Backend::Kernel).map_err(|e| {
                Logger::error(&format!("无法读取统计信息: {e}"));
                io::Error::new(io::ErrorKind::Other, e)
            })?;

            let peer = device.peers.first().ok_or_else(|| {
                Logger::warn("未找到对端");
                io::Error::new(io::ErrorKind::NotFound, "no peer")
            })?;

            Ok(DeviceStats {
                tx_bytes: peer.stats.tx_bytes,
                rx_bytes: peer.stats.rx_bytes,
                last_handshake: peer.stats.last_handshake_time,
            })
        })
        .await
        .unwrap()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeviceStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_handshake: Option<SystemTime>,
}

