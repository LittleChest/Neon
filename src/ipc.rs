use crate::config::Config;
use std::time::Duration;
use tokio::net::UnixStream;
use wireguard_control::{Backend, Device};
use std::io::Write;

pub const SOCKET_PATH: &str = "/dev/warp/ipc.sock";

async fn check_liveness() -> bool {
    if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH).await {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = stream.write_all(b"ping\n").await;
        let mut buf = [0u8; 8];
        if let Ok(n) = stream.read(&mut buf).await {
            return &buf[..n] == b"PONG\n" || &buf[..n] == b"PONG";
        }
    }
    false
}

pub async fn run_action(config_path: &str) {
    let config = Config::load_and_verify(config_path).await.unwrap_or_default();
    let logs_text = read_logs_for_action().await;
    let has_warnings = !logs_text.is_empty();
    
    let hide_action = !config.info.show_on_action && !has_warnings;
    
    if !config.info.allow_mount && hide_action {
        return;
    }

    let sock_exists = std::path::Path::new(SOCKET_PATH).exists();
    if !sock_exists {
        println!("- [i] 正在启动守护进程...");

        let log_path = std::path::Path::new(crate::LOG_FILE);
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match unsafe { libc::fork() } {
            -1 => {
                println!("- [!] 启动失败");
                return;
            }
            0 => {
                unsafe { libc::setsid(); }
                match unsafe { libc::fork() } {
                    -1 => { unsafe { libc::_exit(1); } }
                    0 => {
                        unsafe {
                            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                            if fd >= 0 {
                                libc::dup2(fd, 0); // stdin
                                libc::dup2(fd, 1); // stdout
                                libc::dup2(fd, 2); // stderr
                                if fd > 2 { libc::close(fd); }
                            }
                        }
                        
                        let child_rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all().build().expect("子进程运行时失败");
                        
                        let config_path_clone = config_path.to_string();
                        child_rt.block_on(async move {
                            crate::daemon::runner::run_daemon(&config_path_clone).await;
                        });
                        unsafe { libc::_exit(0); }
                    }
                    _ => { unsafe { libc::_exit(0); } }
                }
            }
            _ => {
                let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let log_path_str = crate::LOG_FILE.to_string();
                let done_clone = done.clone();
                
                let tail_handle = tokio::spawn(async move {
                    tail_log(log_path_str, done_clone).await;
                });

                let mut waited = 0u64;
                let connected = loop {
                    let path_created = std::path::Path::new(SOCKET_PATH).exists();
                    if path_created && check_liveness().await {
                        break true;
                    }
                    if waited >= 15000 {
                        break false;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    waited += 200;
                };

                done.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = tail_handle.await;

                if !connected {
                    println!("- [!] 守护进程启动超时。");
                } else {
                    println!("- [i] 守护进程已成功启动！");
                }
                if config.info.await_on_action { block_1h().await; }
                return;
            }
        }
    }

    let is_alive = check_liveness().await;
    if !is_alive {
        println!("- [!] 守护进程未响应。");
        if config.info.await_on_action { block_1h().await; }
        return;
    }

    if has_warnings {
        println!("{}", logs_text);
    }

    let mut stats_text = String::new();
    for i in 0..100 {
        let name = if i == 0 { "warp".to_string() } else { format!("warp{}", i - 1) };
        let name_clone = name.clone();
        if let Ok(device) = tokio::task::spawn_blocking(move || Device::get(&name_clone.parse().unwrap(), Backend::Kernel)).await.unwrap() {
            stats_text = generate_stats_text(&name, &device, config.hopping.interval_sec);
            break;
        }
    }

    if stats_text.is_empty() {
        println!("- [!] 无法读取接口统计信息。");
    } else {
        println!("{}", stats_text);
    }

    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(crate::LOG_FILE) {
        let _ = writeln!(f, "\n---");
    }

    if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH).await {
        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(b"mark_read\n").await;
    }

    if config.info.await_on_action {
        block_1h().await;
    }
}

pub async fn block_1h() {
    println!("\n- [i] 点按左上角以返回");
    let _ = std::io::stdout().flush();
    tokio::time::sleep(Duration::from_secs(3600)).await;
}

async fn tail_log(path: String, done: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let mut printed_chars = 0;
    loop {
        let is_done = done.load(std::sync::atomic::Ordering::Relaxed);
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            if content.len() > printed_chars {
                let to_print = &content[printed_chars..];
                for line in to_print.lines() {
                    let line_trimmed = line.trim();
                    if line_trimmed != "---" && !line_trimmed.is_empty() {
                        println!("{line}");
                    }
                }
                let _ = std::io::stdout().flush();
                printed_chars = content.len();
            }
        }
        if is_done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn read_logs_for_action() -> String {
    let content = match tokio::fs::read_to_string(crate::LOG_FILE).await {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let mut last_idx = None;
    for (idx, _) in content.match_indices("---") {
        let before = &content[..idx];
        let after = &content[idx + 3..];
        let is_start_of_line = before.is_empty() || before.ends_with('\n');
        let is_end_of_line = after.is_empty() || after.starts_with('\n') || after.starts_with('\r');
        if is_start_of_line && is_end_of_line {
            last_idx = Some(idx);
        }
    }

    let last_chunk = match last_idx {
        Some(idx) => &content[idx + 3..],
        None => &content,
    };

    let mut has_fatal = false;
    for line in last_chunk.lines() {
        if line.starts_with("⛔") {
            has_fatal = true;
            break;
        }
    }

    let mut output = String::new();
    for line in last_chunk.lines() {
        let line = line.trim();
        if line.is_empty() || line == "---" || line.starts_with("--- START_") { continue; }
        
        if has_fatal {
            output.push_str(line);
            output.push('\n');
        } else if line.starts_with("❌") || line.starts_with("⚠️") {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn generate_stats_text(iface_name: &str, device: &Device, refresh_sec: u64) -> String {
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

    let endpoint = peer.config.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "未知".to_string());

    format!(
        "\n  📊 WARP 状态\n  ──────────────\n  状态: {status}\n  上传: {tx}\n  下载: {rx}\n  上次握手: {hs_str}\n  当前端点: {endpoint}\n  接口: {iface_name}\n  监听端口: {listen_port}\n  保持连接: {keepalive}\n  允许IP: {allowed_str}\n  跳跃间隔: {refresh_sec} 秒\n  ──────────────\n\n",
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
