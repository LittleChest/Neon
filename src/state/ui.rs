use crate::state::logger::Logger;
use std::path::Path;

pub struct UiRenderer;

impl UiRenderer {
    fn human_readable(bytes: u64) -> String {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;
        const GIB: u64 = 1024 * MIB;

        if bytes < KIB {
            format!("{} B", bytes)
        } else if bytes < MIB {
            format!("{:.2} KiB", bytes as f64 / KIB as f64)
        } else if bytes < GIB {
            format!("{:.2} MiB", bytes as f64 / MIB as f64)
        } else {
            format!("{:.2} GiB", bytes as f64 / GIB as f64)
        }
    }

    fn format_handshake(last_hs_secs: u64, now_secs: u64) -> String {
        if last_hs_secs == 0 {
            "等待网络连接".to_string()
        } else {
            let diff = now_secs.saturating_sub(last_hs_secs);
            format!("{} 秒前", diff)
        }
    }

    pub async fn update_prop(
        prop_path: &Path,
        tx: u64,
        rx: u64,
        last_hs_secs: u64,
        current_endpoint: &str,
        next_refresh_secs: u64,
    ) -> std::io::Result<()> {
        let tx_str = Self::human_readable(tx);
        let rx_str = Self::human_readable(rx);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let hs_str = Self::format_handshake(last_hs_secs, now);

        let description = Logger::read_state(|state| {
            if let Some(fatal_msg) = &state.fatal {
                return format!("⛔ {}", fatal_msg);
            }
            let mut base = format!(
                "🌐 传输: [↑{} ↓{}] | 🤝 上次握手: {} | ⚡ 端点: {} | 🕗 下次刷新: {} 秒后",
                tx_str, rx_str, hs_str, current_endpoint, next_refresh_secs
            );
            if state.error_count > 0 { base.push_str(&format!(" | ❌ {} 错误", state.error_count)); }
            if state.warning_count > 0 { base.push_str(&format!(" | ⚠️ {} 警告", state.warning_count)); }
            base
        });

        crate::prop::write_prop(prop_path, &description).await
    }
}