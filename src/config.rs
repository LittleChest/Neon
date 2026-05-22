use ipnet::IpNet;
use serde::Deserialize;

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
    pub async fn load_from_file(path: &str) -> std::io::Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}