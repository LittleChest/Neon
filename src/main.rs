mod config;
mod daemon;
mod ipc;
mod prop;
mod state;
mod sys;

const LOG_FILE: &str = "/dev/warp/run.log";

fn main() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(file) = std::fs::File::open("/proc/1/ns/mnt") {
            unsafe {
                let _ = libc::setns(file.as_raw_fd(), libc::CLONE_NEWNS);
            }
        }
    }

    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(|s| s.as_str());

    match sub {
        Some("init") => {
            let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("无法初始化运行时");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
            });
        }

        Some("action") => {
            let config_path = "/data/adb/warp/config.toml";
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("无法初始化运行时");
            rt.block_on(async {
                crate::ipc::run_action(config_path).await;
            });
        }

        Some("test") => {
            let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("无法初始化运行时");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
                match crate::config::Config::load_and_verify(config_path).await {
                    Ok(config) => {
                        use crate::daemon::runner::{WARP_PORTS, WARP_IP_BASE, WARP_IP_COUNT, WARP_PEER_KEY};
                        let pk = match crate::daemon::hopping::decode_b64_key(&config.interface.private_key) {
                            Ok(k) => k,
                            Err(e) => { eprintln!("私钥无效: {e}"); return; }
                        };
                        let pubk = match crate::daemon::hopping::decode_b64_key(WARP_PEER_KEY) {
                            Ok(k) => k,
                            Err(e) => { eprintln!("公钥无效: {e}"); return; }
                        };
                        let engine = crate::daemon::hopping::HoppingEngine::new(
                            pk, pubk, None,
                        );
                        crate::daemon::hopping::run_test(
                            &engine, WARP_PORTS, &WARP_IP_BASE, WARP_IP_COUNT,
                        ).await;
                    }
                    Err(e) => eprintln!("配置加载失败: {e}"),
                }
            });
        }

        _ => {
            let config_path = "/data/adb/warp/config.toml";
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("tokio 运行时失败");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
                crate::daemon::runner::run_daemon(config_path).await;
            });
        }
    }
}
