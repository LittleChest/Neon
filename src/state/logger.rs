use std::sync::{OnceLock, RwLock};

#[derive(Debug, Default)]
pub struct LogState {
    pub fatal: Option<String>,
    pub error_count: usize,
    pub warning_count: usize,
}

static GLOBAL_LOG: OnceLock<RwLock<LogState>> = OnceLock::new();

pub struct Logger;

impl Logger {
    pub fn init() {
        GLOBAL_LOG.get_or_init(|| RwLock::new(LogState::default()));
    }

    fn get_state() -> std::sync::RwLockWriteGuard<'static, LogState> {
        GLOBAL_LOG.get().expect("INITIALIZING").write().unwrap()
    }

    pub fn read_state<F, R>(f: F) -> R
    where
        F: FnOnce(&LogState) -> R,
    {
        let state = GLOBAL_LOG.get().expect("INITIALIZING").read().unwrap();
        f(&state)
    }

    pub fn fatal(msg: &str) {
        let mut state = Self::get_state();
        state.fatal = Some(msg.to_string());
        eprintln!("⛔ [致命错误] {}", msg);
    }

    pub fn error(msg: &str) {
        let mut state = Self::get_state();
        state.error_count += 1;
        eprintln!("❌ [错误] {}", msg);
    }

    pub fn warn(msg: &str) {
        let mut state = Self::get_state();
        state.warning_count += 1;
        println!("⚠️ [警告] {}", msg);
    }

    pub fn info(msg: &str) {
        println!("ℹ️ [信息] {}", msg);
    }
}