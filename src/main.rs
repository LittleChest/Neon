mod config;
mod daemon;
mod prop;
mod state;
mod sys;

const LOG_FILE: &str = "/dev/warp/run.log";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(|s| s.as_str());

    match sub {
        Some("init") => {
            let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("无法初始化运行时");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
                crate::daemon::runner::init(config_path).await;
            });
        }

        Some("action") => {
            match std::fs::read_to_string(LOG_FILE) {
                Ok(content) => {
                    let entries: Vec<&str> = content
                        .lines()
                        .rev()
                        .filter(|l| l.starts_with("⛔") || l.starts_with("❌") || l.starts_with("⚠️"))
                        .take(5)
                        .collect();
                    if entries.is_empty() {
                    } else {
                        for line in entries.iter().rev() {
                            println!("{line}");
                        }
                    }
                }
                Err(_) => {}
            }
        }

        _ => {
            let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("tokio 运行时失败");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
                if let Some(state) = crate::daemon::runner::init(config_path).await {
                    crate::daemon::runner::run_loop(state).await;
                }
            });
        }
    }
}
