use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub routing: RoutingConfig,
    pub hopping: HoppingConfig,
    pub info: InfoConfig,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub mtu: u32,
    pub ipv4: IpNet,
    pub ipv6: IpNet,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct RoutingConfig {
    pub must_proxy: Vec<IpNet>,
    pub must_bypass: Vec<IpNet>,
    pub rules_ips: Vec<IpNet>,
    pub is_whitelist: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct HoppingConfig {
    pub concurrent_tests: usize,
    pub interval_sec: u64,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct InfoConfig {
    pub show_in_manager: bool,
    pub refresh_sec: u64,
    pub show_on_action: bool,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            mtu: 1280,
            ipv4: "172.16.0.2/32".parse().unwrap(),
            ipv6: "2606:4700:1111::2/128".parse().unwrap(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let parse = |s: &str| s.parse::<IpNet>().unwrap();
        Self {
            must_proxy: vec![parse("100.96.0.0/12")],
            must_bypass: vec![
                parse("0.0.0.0/8"), parse("10.0.0.0/8"), parse("100.64.0.0/10"),
                parse("127.0.0.0/8"), parse("169.254.0.0/16"), parse("172.16.0.0/12"),
                parse("192.0.0.0/24"), parse("192.0.2.0/24"), parse("192.88.99.0/24"),
                parse("192.168.0.0/16"), parse("198.18.0.0/15"), parse("198.51.100.0/24"),
                parse("203.0.113.0/24"), parse("224.0.0.0/4"), parse("240.0.0.0/4"),
                parse("255.255.255.255/32"),
            ],
            rules_ips: vec![],
            is_whitelist: false,
        }
    }
}

impl Default for HoppingConfig {
    fn default() -> Self {
        Self { concurrent_tests: 8, interval_sec: 60 }
    }
}

impl Default for InfoConfig {
    fn default() -> Self {
        Self { show_in_manager: true, refresh_sec: 60, show_on_action: true }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: InterfaceConfig::default(),
            routing: RoutingConfig::default(),
            hopping: HoppingConfig::default(),
            info: InfoConfig::default(),
        }
    }
}

impl Config {
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Config::default()).unwrap_or_default()
    }

    pub async fn ensure_exists<P: AsRef<Path>>(path: P) -> Result<(), String> {
        let p = path.as_ref();
        if tokio::fs::metadata(p).await.is_ok() {
            return Ok(());
        }
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| format!("无法创建配置目录: {e}"))?;
        }
        tokio::fs::write(p, Self::default_toml()).await.map_err(|e| format!("无法写入默认配置: {e}"))?;
        Ok(())
    }

    pub async fn load_and_verify<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("无法读取配置文件: {}", e))?;
            
        let mut config: Config = toml::from_str(&content)
            .map_err(|e| format!("无法解析配置文件: {}", e))?;

        Self::verify_wg_key(&config.interface.private_key)?;

        if config.hopping.concurrent_tests == 0 {
            config.hopping.concurrent_tests = 1;
        }

        Ok(config)
    }

    fn verify_wg_key(key_str: &str) -> Result<(), String> {
        let mut buf = [0u8; 64];
        let len = STANDARD.decode_slice(key_str.trim(), &mut buf)
            .map_err(|e| format!("私钥 Base64 格式错误: {}", e))?;
        if len != 32 {
            return Err(format!("私钥必须是 32 字节，传入了 {} 字节。", len));
        }
        Ok(())
    }
}