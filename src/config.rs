use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub routing: RoutingConfig,
    pub hopping: HoppingConfig,
    pub info: InfoConfig,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub mtu: u32,
    pub ipv4: IpNet,
    pub ipv6: IpNet,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct RoutingConfig {
    pub must_proxy: Vec<IpNet>,
    pub must_bypass: Vec<IpNet>,
    pub rules_ips: Vec<IpNet>,
    pub is_whitelist: bool,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct HoppingConfig {
    pub concurrent_tests: usize,
    pub interval_sec: u64,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct InfoConfig {
    pub show_in_manager: bool,
    pub refresh_sec: u64,
    pub show_on_action: bool,
}

impl Config {
    pub async fn load_and_verify<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("无法读取配置文件: {}", e))?;
            
        let config: Config = toml::from_str(&content)
            .map_err(|e| format!("无法解析配置文件: {}", e))?;

        Self::verify_wg_key(&config.interface.private_key)?;

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