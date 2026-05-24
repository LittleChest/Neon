use crate::ipc::server::SOCKET_PATH;
use std::io;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn run_start() {
    let marker = format!(
        "--- START_{} ---",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(crate::LOG_FILE) {
        let _ = writeln!(f, "\n{}\n", marker);
    }

    match try_start(marker).await {
        Ok(_) => {
            block_1h().await;
        }
        Err(e) => {
            println!("- [!] 启动失败: {e}");
            block_1h().await;
        }
    }
}

async fn try_start(marker: String) -> io::Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone(), marker));

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
    let marker = format!(
        "--- START_{} ---",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(crate::LOG_FILE) {
        let _ = writeln!(f, "\n{}\n", marker);
    }

    match try_action(marker).await {
        Ok(_) => {}
        Err(e) => {
            println!("- [!] 无法与守护进程通信: {e}");
            block_1h().await;
        }
    }
}

async fn try_action(marker: String) -> io::Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    writer.write_all(b"action\n").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        match line.as_str() {
            "WAIT" => {
                println!("- [i] 想要停用服务吗？请再次点按执行。");
                block_1h().await;
                break;
            }
            "EXIT" => {
                let done = Arc::new(AtomicBool::new(false));
                let tail = tokio::spawn(tail_log(crate::LOG_FILE.to_string(), done.clone(), marker.clone()));
                while let Ok(Some(line)) = lines.next_line().await {
                    if line == "DONE" {
                        break;
                    }
                }
                done.store(true, Ordering::Relaxed);
                let _ = tail.await;
                println!("\n- [i] 服务已停用。");
                block_1h().await;
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

pub async fn block_1h() {
    println!("\n- [i] 点按左上角以返回");
    let _ = std::io::stdout().flush();
    tokio::time::sleep(Duration::from_secs(3600)).await;
}

async fn tail_log(path: String, done: Arc<AtomicBool>, marker: String) {
    let mut printed_chars = 0;
    loop {
        let is_done = done.load(Ordering::Relaxed);
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            if let Some(idx) = content.rfind(&marker) {
                let new_text = &content[idx + marker.len()..];
                if new_text.len() > printed_chars {
                    let to_print = &new_text[printed_chars..];
                    for line in to_print.lines() {
                        let line_trimmed = line.trim();
                        if line_trimmed != "---" && !line_trimmed.is_empty() {
                            println!("{line}");
                        }
                    }
                    let _ = std::io::stdout().flush();
                    printed_chars = new_text.len();
                }
            }
        }
        if is_done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
