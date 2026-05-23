mod config;
mod daemon;
mod ipc;
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
            let _ = crate::config::Config::ensure_exists(config_path);
        }

        Some("action") => {
            let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("无法初始化运行时");

            let daemon_running = rt.block_on(crate::ipc::client::is_daemon_running());

            if daemon_running {
                rt.block_on(async {
                    if let Err(e) = crate::ipc::client::run_action().await {
                        eprintln!("- [!] 无法与守护进程通信: {e}");
                    }
                });
            } else {
                {
                    let p = std::path::Path::new(config_path);
                    if !p.exists() {
                        if let Some(parent) = p.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = std::fs::write(p, crate::config::Config::default_toml());
                    }
                }

                match unsafe { libc::fork() } {
                    -1 => {
                        eprintln!("- [!] fork 失败");
                    }
                    0 => {
                        unsafe { libc::setsid(); }
                        unsafe {
                            libc::close(0); // stdin
                            libc::close(1); // stdout
                            libc::close(2); // stderr
                        }
                        let child_rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all().build().expect("子进程运行时失败");
                        child_rt.block_on(async {
                            if let Some(state) = crate::daemon::runner::init(config_path, None).await {
                                crate::daemon::runner::run_loop(state).await;
                            }
                        });
                        unsafe { libc::_exit(0); }
                    }
                    _ => {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        rt.block_on(async {
                            if let Err(e) = crate::ipc::client::run_start().await {
                                eprintln!("- [!] 启动失败: {e}");
                            }
                        });
                    }
                }
            }
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
            let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("/data/adb/warp/config.toml");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("tokio 运行时失败");
            rt.block_on(async {
                let _ = crate::config::Config::ensure_exists(config_path).await;
                if let Some(state) = crate::daemon::runner::init(config_path, None).await {
                    crate::daemon::runner::run_loop(state).await;
                }
            });
        }
    }
}
