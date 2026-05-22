use crate::config::Config;
use crate::daemon::hopping::{decode_b64_key, HoppingEngine};
use crate::state::logger::Logger;
use crate::state::ui::UiRenderer;
use crate::sys::interface::InterfaceManager;
use crate::sys::mount::MountManager;
use crate::sys::routing::RoutingManager;
use crate::sys::wg::WgManager;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time;
use wireguard_control::InterfaceName;

pub(crate) const WARP_PEER_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
pub(crate) const WARP_IP_BASE: [u8; 4] = [162, 159, 193, 1];
pub(crate) const WARP_IP_COUNT: u8 = 10;
const FWMARK: u32 = 0x20000;
const WARP_TABLE: u32 = 0x20000;

pub(crate) const WARP_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
    955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
    7559, 8319, 8742, 8854, 8886,
];

pub struct DaemonState {
    pub config: Config,
    pub iface: InterfaceName,
    pub pool: Vec<SocketAddr>,
    pub current_endpoint: SocketAddr,
    pub hopping: HoppingEngine,
    pub prop_path: PathBuf,
}

pub async fn init(config_path: &str) -> Option<DaemonState> {
    let config = Config::load_and_verify(config_path).await.ok()?;

    let module_dir = Path::new("/data/adb/modules/WARP");
    let tmp_dir = Path::new("/dev/warp");
    MountManager::setup_magisk_env(module_dir, &[tmp_dir]).await.ok()?;

    Logger::init(crate::LOG_FILE);
    Logger::info("载入中...");

    WgManager::check_kernel_support().ok()?;
    let iface = WgManager::find_available_name().ok()?;

    let (if_mgr, conn) = InterfaceManager::new().ok()?;
    tokio::spawn(conn);

    let iface_name = iface.to_string();
    let iface_index = if_mgr.create_wg(&iface_name, config.interface.mtu).await.ok()?;
    if_mgr.add_ip(iface_index, &config.interface.ipv4).await.ok()?;
    if_mgr.add_ip(iface_index, &config.interface.ipv6).await.ok()?;
    if_mgr.set_up(iface_index).await.ok()?;

    WgManager::apply_device_config(&iface, &config.interface.private_key, FWMARK, None).ok()?;

    let pool = build_endpoint_pool();
    let first_ep = pool[0];
    WgManager::set_peer(&iface, WARP_PEER_KEY, first_ep, 25).ok()?;

    let (rt_mgr, rt_conn) = RoutingManager::new().ok()?;
    tokio::spawn(rt_conn);
    rt_mgr.add_default_route(iface_index, WARP_TABLE).await.ok()?;
    rt_mgr.apply_rules(
        &config.routing.must_proxy,
        &config.routing.must_bypass,
        &config.routing.rules_ips,
        config.routing.is_whitelist,
        WARP_TABLE, 0, FWMARK,
    ).await.ok()?;

    let pk = decode_b64_key(&config.interface.private_key).ok()?;
    let pubk = decode_b64_key(WARP_PEER_KEY).ok()?;
    let hopping = HoppingEngine::new(pk, pubk, None, Duration::from_secs(5));
    let prop_path = module_dir.join("module.prop");

    Logger::info("正在启动守护进程");
    Some(DaemonState { config, iface, pool, current_endpoint: first_ep, hopping, prop_path })
}

pub async fn run_loop(mut state: DaemonState) {
    let hopping_interval = Duration::from_secs(state.config.hopping.interval_sec);
    let ui_interval = Duration::from_secs(state.config.info.refresh_sec);
    let mut hopping_tick = time::interval(hopping_interval);
    let mut ui_tick = time::interval(ui_interval);

    loop {
        tokio::select! {
            _ = hopping_tick.tick() => {
                if let Some(best) = state.hopping
                    .find_best(&state.pool, state.config.hopping.concurrent_tests).await
                {
                    if best != state.current_endpoint {
                        if WgManager::update_endpoint(&state.iface, WARP_PEER_KEY, best).is_ok() {
                            state.current_endpoint = best;
                        }
                    }
                }
            }

            _ = ui_tick.tick() => {
                if MountManager::is_safe_tmpfs(&state.prop_path).unwrap_or(false) {
                    if let Ok(stats) = WgManager::get_stats(&state.iface) {
                        let hs = stats.last_handshake
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        let _ = UiRenderer::update_prop(
                            &state.prop_path,
                            stats.tx_bytes,
                            stats.rx_bytes,
                            hs,
                            &state.current_endpoint.to_string(),
                            hopping_interval.as_secs(),
                        ).await;
                    }
                }
            }
        }
    }
}

fn build_endpoint_pool() -> Vec<SocketAddr> {
    let mut pool = Vec::with_capacity(WARP_IP_COUNT as usize * WARP_PORTS.len());
    for i in 0..WARP_IP_COUNT {
        let ip = Ipv4Addr::new(
            WARP_IP_BASE[0], WARP_IP_BASE[1], WARP_IP_BASE[2], WARP_IP_BASE[3] + i,
        );
        for &port in WARP_PORTS {
            pool.push(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
    }
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let seed = RandomState::new().build_hasher().finish();
    let mut r = seed;
    for i in (1..pool.len()).rev() {
        r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (r as usize) % (i + 1);
        pool.swap(i, j);
    }
    pool
}
