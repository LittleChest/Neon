use crate::state::logger::Logger;
use std::io;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use wireguard_control::{Backend, Device, InterfaceName};

pub const SOCKET_PATH: &str = "/dev/warp/ipc.sock";
const PRE_DISABLE_SECS: u64 = 5;

pub enum IpcResult {
    StartRequested,
    DeinitRequested,
    ActionCompleted,
    StatsOnly,
    Error,
}

pub async fn start_listening() -> io::Result<UnixListener> {
    let _ = tokio::fs::remove_file(SOCKET_PATH).await;
    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let listener = UnixListener::bind(SOCKET_PATH)?;
    Logger::info(&format!("信道监听: {SOCKET_PATH}"));
    Ok(listener)
}

pub async fn handle_next(
    listener: &UnixListener,
    iface_name: &str,
    config_path: &str,
    pre_disable: Option<Instant>,
    current_endpoint: &str,
    refresh_sec: u64,
) -> (IpcResult, Option<tokio::net::unix::OwnedWriteHalf>) {
    let (stream, _) = match listener.accept().await {
        Ok(v) => v,
        Err(e) => {
            Logger::error(&format!("信道接受连接失败: {e}"));
            return (IpcResult::Error, None);
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let request = match lines.next_line().await {
        Ok(Some(line)) => line.trim().to_string(),
        _ => return (IpcResult::Error, None),
    };

    match request.as_str() {
        "stats" => {
            let text = read_stats(iface_name, current_endpoint, refresh_sec);
            let _ = writer.write_all(text.as_bytes()).await;
            (IpcResult::StatsOnly, None)
        }
        "start" => (IpcResult::StartRequested, None),
        "disable" => (IpcResult::DeinitRequested, Some(writer)),
        "action" => {
            let result = handle_action(&mut writer, iface_name, config_path, pre_disable, current_endpoint, refresh_sec).await;
            match result {
                IpcResult::DeinitRequested => (result, Some(writer)),
                _ => (result, None),
            }
        }
        _ => {
            let _ = writer.write_all(b"ERR: unknown command\n").await;
            (IpcResult::Error, None)
        }
    }
}

async fn handle_action(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    iface_name: &str,
    config_path: &str,
    pre_disable: Option<Instant>,
    current_endpoint: &str,
    refresh_sec: u64,
) -> IpcResult {
    let effective_pre_disable = pre_disable.filter(|t| t.elapsed().as_secs() < PRE_DISABLE_SECS);

    let config_diff = check_config_diff(config_path).await;

    if config_diff {
        let _ = writer
            .write_all("- [i] 正在应用配置...\nEXIT\n".as_bytes())
            .await;
    }

    if effective_pre_disable.is_some() {
        let _ = writer
            .write_all("- [i] 正在停用服务...\nEXIT\n".as_bytes())
            .await;
        return IpcResult::DeinitRequested;
    }

    let stats_text = read_stats(iface_name, current_endpoint, refresh_sec);
    let _ = writer.write_all(stats_text.as_bytes()).await;
    let _ = writer
        .write_all("- [!] 未发现配置文件变更。\n- [i] 想要停用服务吗？请在关闭此窗口后的 5 秒内再次点按。\nWAIT\n".as_bytes())
        .await;

    let _ = writer.shutdown().await;

    IpcResult::ActionCompleted
}

async fn check_config_diff(_config_path: &str) -> bool {
    // @TODO
    false
}

fn read_stats(iface_name: &str, current_endpoint: &str, refresh_sec: u64) -> String {
    let iface: InterfaceName = match iface_name.parse() {
        Ok(n) => n,
        Err(_) => return String::new(),
    };
    let device = match Device::get(&iface, Backend::Kernel) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let peer = match device.peers.first() {
        Some(p) => p,
        None => return String::new(),
    };

    let tx = human_readable(peer.stats.tx_bytes);
    let rx = human_readable(peer.stats.rx_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (hs_str, connected) = match peer.stats.last_handshake_time {
        Some(t) => {
            let hs = t
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if hs == 0 {
                ("等待网络连接".to_string(), false)
            } else {
                (format!("{} 秒前", now.saturating_sub(hs)), true)
            }
        }
        None => ("等待网络连接".to_string(), false),
    };

    let status = if connected { "✅ 已连接" } else { "❌ 未连接" };

    let listen_port = device.listen_port.map(|p| p.to_string()).unwrap_or_else(|| "随机".to_string());
    let keepalive = peer.config.persistent_keepalive_interval
        .map(|s| format!("{s} 秒"))
        .unwrap_or_else(|| "关闭".to_string());
    let allowed_ips: Vec<String> = peer.config.allowed_ips.iter()
        .map(|a| format!("{}/{}", a.address, a.cidr))
        .collect();
    let allowed_str = if allowed_ips.is_empty() { "无".to_string() } else { allowed_ips.join(", ") };

    format!(
        "\n  📊 WARP 状态\n  ──────────────\n  状态: {status}\n  上传: {tx}\n  下载: {rx}\n  上次握手: {hs_str}\n  当前端点: {current_endpoint}\n  接口: {iface_name}\n  监听端口: {listen_port}\n  保持连接: {keepalive}\n  允许IP: {allowed_str}\n  跳跃间隔: {refresh_sec} 秒\n  ──────────────\n\n",
    )
}

fn human_readable(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes < KIB {
        format!("{} B", bytes)
    } else if bytes < MIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    }
}
