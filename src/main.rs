mod config;
mod daemon;
mod prop;
mod state;
mod sys;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("/data/adb/warp/config.toml");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("无法初始化运行时");

    rt.block_on(async {
        crate::state::logger::Logger::init();
        if let Some(state) = crate::daemon::runner::init(config_path).await {
            crate::daemon::runner::run_loop(state).await;
        }
    });
}
