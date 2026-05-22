use std::path::Path;
use tokio::fs;

pub const PROP_BASE: &str = "id=WARP\nname=WARP\nversion=🌈 Neon\nversionCode=2\nauthor=LittleChest\n";

pub const PROP_DESC_STOPPED: &str = "🚫 已停止";

pub async fn read_prop(path: &Path) -> std::io::Result<String> {
    match fs::read_to_string(path).await {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PROP_BASE.to_string()),
        Err(e) => Err(e),
    }
}

pub async fn write_prop(path: &Path, description: &str) -> std::io::Result<()> {
    let existing = read_prop(path).await.unwrap_or_else(|_| PROP_BASE.to_string());

    let mut new_content = String::with_capacity(existing.len() + description.len() + 32);
    let mut replaced = false;

    for line in existing.lines() {
        if line.starts_with("description=") {
            new_content.push_str(&format!("description={}\n", description));
            replaced = true;
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !replaced {
        new_content.push_str(&format!("description={}\n", description));
    }

    fs::write(path, new_content).await
}

pub async fn write_stopped(path: &Path) -> std::io::Result<()> {
    write_prop(path, PROP_DESC_STOPPED).await
}
