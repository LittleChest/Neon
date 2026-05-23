use crate::ipc::server::SOCKET_PATH;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn run_start() {
    match try_start().await {
        Ok(_) => {
            countdown(10).await;
        }
        Err(e) => {
            eprintln!("- [!] 启动失败: {e}");
            countdown(10).await;
        }
    }
}

async fn try_start() -> io::Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone()));

    let mut waited = 0u64;
    let stream = loop {
        match UnixStream::connect(SOCKET_PATH).await {
            Ok(s) => break s,
            Err(e) => {
                if waited >= 15000 {
                    done.store(true, Ordering::Relaxed);
                    let _ = tail.await;
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                waited += 200;
            }
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"start\n").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        if line == "DONE" {
            break;
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = tail.await;
    Ok(())
}

pub async fn run_action() {
    match try_action().await {
        Ok(_) => {
        }
        Err(e) => {
            eprintln!("- [!] 无法与守护进程通信: {e}");
            countdown(10).await;
        }
    }
}

async fn try_action() -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"action\n").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        match line.as_str() {
            "WAIT" => {
                println!("- [i] 再次点按以停用，或等待自动关闭...");
                countdown(10).await;
                break;
            }
            "EXIT" => {
                let done = Arc::new(AtomicBool::new(false));
                let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone()));
                while let Ok(Some(line)) = lines.next_line().await {
                    if line == "DONE" {
                        break;
                    }
                }
                done.store(true, Ordering::Relaxed);
                let _ = tail.await;
                countdown(10).await;
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

pub async fn is_daemon_running() -> bool {
    UnixStream::connect(SOCKET_PATH).await.is_ok()
}

pub async fn countdown(secs: u64) {
    let mut remaining = secs;
    while remaining > 0 {
        eprintln!("\n- [i] 将在 {remaining} 秒后关闭...");
        tokio::time::sleep(Duration::from_secs(1)).await;
        remaining -= 1;
    }
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
