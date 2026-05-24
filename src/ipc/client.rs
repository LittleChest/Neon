use crate::ipc::server::SOCKET_PATH;
use std::io;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn run_start() {
    let initial_pos = match tokio::fs::metadata(crate::LOG_FILE).await {
        Ok(meta) => meta.len(),
        Err(_) => 0,
    };
    
    match try_start(initial_pos).await {
        Ok(_) => {
            countdown(10).await;
        }
        Err(e) => {
            println!("- [!] 启动失败: {e}");
            countdown(10).await;
        }
    }
}

async fn try_start(initial_pos: u64) -> io::Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone(), initial_pos));

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

    match tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line == "DONE" {
                break;
            }
        }
    }).await {
        Ok(_) => {},
        Err(_) => {
            println!("- [!] 守护进程无响应，请查看管理器日志。");
        }
    }
    
    done.store(true, Ordering::Relaxed);
    let _ = tail.await;
    Ok(())
}

pub async fn run_action() {
    let initial_pos = match tokio::fs::metadata(crate::LOG_FILE).await {
        Ok(meta) => meta.len(),
        Err(_) => 0,
    };

    match try_action(initial_pos).await {
        Ok(_) => {}
        Err(e) => {
            println!("- [!] 无法与守护进程通信: {e}");
            countdown(10).await;
        }
    }
}

async fn try_action(initial_pos: u64) -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"action\n").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        match line.as_str() {
            "WAIT" => {
                println!("- [i] 想要停用服务吗？请再次点按动作执行。");
                countdown(10).await;
                break;
            }
            "EXIT" => {
                let done = Arc::new(AtomicBool::new(false));
                let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone(), initial_pos));
                while let Ok(Some(line)) = lines.next_line().await {
                    if line == "DONE" {
                        break;
                    }
                }
                done.store(true, Ordering::Relaxed);
                let _ = tail.await;
                println!("\n- [i] 服务已停用。");
                countdown(3).await;
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
    println!();
    while remaining > 0 {
        print!("\r- [i] 窗口将在 {} 秒后自动关闭...   ", remaining);
        let _ = std::io::stdout().flush();
        tokio::time::sleep(Duration::from_secs(1)).await;
        remaining -= 1;
    }
}

async fn tail_log(path: String, done: Arc<AtomicBool>, mut pos: u64) {
    loop {
        if done.load(Ordering::Relaxed) {
            if let Ok(mut f) = tokio::fs::File::open(&path).await {
                let _ = f.seek(io::SeekFrom::Start(pos)).await;
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    if line.trim() != "---" {
                        print!("{line}");
                    }
                    line.clear();
                }
            }
            let _ = std::io::stdout().flush();
            break;
        }
        match tokio::fs::File::open(&path).await {
            Ok(mut f) => {
                let _ = f.seek(io::SeekFrom::Start(pos)).await;
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    if line.trim() != "---" {
                        print!("{line}");
                    }
                    line.clear();
                }
                let _ = std::io::stdout().flush();
                pos = reader.stream_position().await.unwrap_or(pos);
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => break,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
