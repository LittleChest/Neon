use crate::ipc::server::SOCKET_PATH;
use crate::state::ui::UiRenderer;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use wireguard_control::{Backend, Device, InterfaceName};

pub async fn run_start() -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"start\n").await?;

    let done = Arc::new(AtomicBool::new(false));
    let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone()));

    while let Ok(Some(line)) = lines.next_line().await {
        if line == "DONE" {
            done.store(true, Ordering::Relaxed);
            break;
        }
    }
    let _ = tail.await;
    Ok(())
}

pub async fn run_action() -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"action\n").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        match line.as_str() {
            "WAIT" => std::future::pending::<()>().await,
            "EXIT" => {
                let done = Arc::new(AtomicBool::new(false));
                let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone()));
                while let Ok(Some(line)) = lines.next_line().await {
                    if line == "DONE" {
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                let _ = tail.await;
                break;
            }
            "DONE" => break,
            _ => {
                println!("{line}");
            }
        }
    }
    Ok(())
}

pub async fn run_disable() -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"disable\n").await?;

    let done = Arc::new(AtomicBool::new(false));
    let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone()));

    while let Ok(Some(line)) = lines.next_line().await {
        if line == "DONE" {
            done.store(true, Ordering::Relaxed);
            break;
        }
    }
    let _ = tail.await;
    Ok(())
}

pub fn print_stats(iface_name: &str) {
    let iface: InterfaceName = match iface_name.parse() {
        Ok(n) => n,
        Err(_) => return,
    };
    let device = match Device::get(&iface, Backend::Kernel) {
        Ok(d) => d,
        Err(_) => return,
    };
    let peer = match device.peers.first() {
        Some(p) => p,
        None => return,
    };

    let tx = UiRenderer::human_readable(peer.stats.tx_bytes);
    let rx = UiRenderer::human_readable(peer.stats.rx_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let hs_str = match peer.stats.last_handshake_time {
        Some(t) => {
            let hs = t
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if hs == 0 {
                "等待网络连接".to_string()
            } else {
                format!("{} 秒前", now.saturating_sub(hs))
            }
        }
        None => "等待网络连接".to_string(),
    };

    println!("↑{tx} ↓{rx} | 🤝 {hs_str}");
}

pub async fn is_daemon_running() -> bool {
    UnixStream::connect(SOCKET_PATH).await.is_ok()
}

async fn tail_log(path: String, done: Arc<AtomicBool>) {
    let mut pos: u64 = 0;
    loop {
        if done.load(Ordering::Relaxed) {
            if let Ok(mut f) = tokio::fs::File::open(&path).await {
                let _ = f.seek(std::io::SeekFrom::Start(pos)).await;
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    print!("{line}");
                    line.clear();
                }
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            break;
        }
        match tokio::fs::File::open(&path).await {
            Ok(mut f) => {
                let _ = f.seek(std::io::SeekFrom::Start(pos)).await;
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    print!("{line}");
                    line.clear();
                }
                let _ = std::io::Write::flush(&mut std::io::stdout());
                pos = reader.stream_position().await.unwrap_or(pos);
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => break,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn find_warp_iface() -> Option<String> {
    for i in 0..10 {
        let name = if i == 0 {
            "warp".to_string()
        } else {
            format!("warp{}", i - 1)
        };
        if let Ok(iface) = name.parse::<InterfaceName>() {
            if Device::get(&iface, Backend::Kernel).is_ok() {
                return Some(name);
            }
        }
    }
    None
}
