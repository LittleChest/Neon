use std::path::Path;
use std::sync::{OnceLock, RwLock};
const MAX_LINES: usize = 100;

#[derive(Debug, Default)]
pub struct LogState {
    pub fatal: Option<String>,
    pub error_count: usize,
    pub warning_count: usize,
}

struct LoggerInner {
    state: RwLock<LogState>,
    file: &'static Path,
}

static GLOBAL_LOG: OnceLock<LoggerInner> = OnceLock::new();

pub struct Logger;

impl Logger {
    pub fn init(log_path: &'static str) {
        let path = Path::new(log_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        GLOBAL_LOG
            .set(LoggerInner { state: RwLock::new(LogState::default()), file: path })
            .ok();
    }

    fn inner() -> &'static LoggerInner {
        GLOBAL_LOG.get().expect("Logger 未初始化")
    }

    pub fn read_state<F, R>(f: F) -> R
    where
        F: FnOnce(&LogState) -> R,
    {
        f(&Self::inner().state.read().unwrap())
    }

    fn append_line(entry: &str) {
        let path = Self::inner().file;
        let mut lines: Vec<String> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|s| s.to_string())
            .collect();
        lines.push(entry.to_string());
        if lines.len() > MAX_LINES {
            lines.drain(0..lines.len() - MAX_LINES);
        }
        let _ = std::fs::write(path, lines.join("\n"));
    }

    pub fn fatal(msg: &str) {
        let mut state = Self::inner().state.write().unwrap();
        state.fatal = Some(msg.to_string());
        drop(state);
        let entry = format!("⛔ {msg}");
        println!("{entry}");
        Self::append_line(&entry);
    }

    pub fn error(msg: &str) {
        Self::inner().state.write().unwrap().error_count += 1;
        let entry = format!("❌ {msg}");
        println!("{entry}");
        Self::append_line(&entry);
    }

    pub fn warn(msg: &str) {
        Self::inner().state.write().unwrap().warning_count += 1;
        let entry = format!("⚠️ {msg}");
        println!("{entry}");
        Self::append_line(&entry);
    }

    pub fn info(msg: &str) {
        let entry = format!("ℹ️ {msg}");
        println!("{entry}");
        Self::append_line(&entry);
    }
}