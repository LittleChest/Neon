use crate::config::Config;
use crate::daemon::hopping::{decode_b64_key, HoppingEngine};
use crate::ipc::server::{self, IpcResult};
use crate::state::logger::Logger;
use crate::state::ui::UiRenderer;
use crate::sys::interface::InterfaceManager;
use crate::sys::mount::MountManager;
use crate::sys::routing::RoutingManager;
use crate::sys::wg::WgManager;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
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
    pub config_path: String,
    pub iface: InterfaceName,
    pub iface_str: String,
    pub pool: Vec<SocketAddr>,
    pub current_endpoint: SocketAddr,
    pub hopping: std::sync::Arc<HoppingEngine>,
    pub prop_path: PathBuf,
    pub pre_disable_since: Option<Instant>,
    pub ipc_listener: Option<tokio::net::UnixListener>,
}

pub async fn init(
    config_path: &str,
    existing_listener: Option<tokio::net::UnixListener>,
) -> Option<DaemonState> {
    let config = Config::load_and_verify(config_path).await.ok()?;

    let module_dir = Path::new("/data/adb/modules/WARP");
    let tmp_dir = Path::new("/dev/warp");
    MountManager::setup_magisk_env(module_dir, &[tmp_dir]).await.ok()?;

    Logger::init(crate::LOG_FILE);
    Logger::info("载入中...");

    let _ = tokio::fs::remove_file("/data/adb/modules/WARP/disable").await;

    let ipc_listener = match existing_listener {
        Some(l) => l,
        None => match server::start_listening().await {
            Ok(l) => l,
            Err(e) => {
                Logger::fatal(&format!("无法启动信道: {e}"));
                return None;
            }
        },
    };

    let pool = build_endpoint_pool();
    
    let pk = match decode_b64_key(&config.interface.private_key) {
        Ok(k) => k,
        Err(e) => { Logger::fatal(&format!("私钥解析失败: {e}")); return None; }
    };
    let pubk = match decode_b64_key(WARP_PEER_KEY) {
        Ok(k) => k,
        Err(e) => { Logger::fatal(&format!("公钥解析失败: {e}")); return None; }
    };
    let hopping = std::sync::Arc::new(HoppingEngine::new(pk, pubk, None));

    loop {
        if hopping.check_connectivity().await {
            break;
        }
        Logger::info("等待网络连接...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    let first_ep = loop {
        Logger::info("正在探测可用端点...");
        if let Some(ep) = hopping.race_for_first(&pool, config.hopping.concurrent_tests).await {
            Logger::info(&format!("选定端点: {}", ep));
            break ep;
        }
        Logger::warn("所有探测均超时，10秒后重试...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    if let Err(e) = WgManager::check_kernel_support().await {
        Logger::fatal(&format!("内核不支持 WireGuard: {e}"));
        return None;
    }

    let iface = match WgManager::find_available_name().await {
        Ok(i) => i,
        Err(e) => { Logger::fatal(&format!("获取接口名失败: {e}")); return None; }
    };

    let (if_mgr, conn) = match InterfaceManager::new() {
        Ok(c) => c,
        Err(e) => { Logger::fatal(&format!("网卡失败: {e}")); return None; }
    };
    tokio::spawn(conn);

    let iface_name = iface.to_string();
    let iface_index = match if_mgr.create_wg(&iface_name, config.interface.mtu).await {
        Ok(i) => i,
        Err(e) => { Logger::fatal(&format!("创建接口失败: {e}")); return None; }
    };

    let _ = if_mgr.add_ip(iface_index, &config.interface.ipv4).await;
    let _ = if_mgr.add_ip(iface_index, &config.interface.ipv6).await;

    if let Err(e) = if_mgr.set_up(iface_index).await {
        Logger::fatal(&format!("启用接口失败: {e}"));
        return None;
    }

    if let Err(e) = WgManager::apply_device_config(iface.clone(), config.interface.private_key.clone(), FWMARK, None).await {
        Logger::fatal(&format!("下发配置失败: {e}"));
        return None;
    }

    if let Err(e) = WgManager::set_peer(iface.clone(), WARP_PEER_KEY.to_string(), first_ep, 25).await {
        Logger::fatal(&format!("设置对端失败: {e}"));
        return None;
    }

    let (rt_mgr, rt_conn) = match RoutingManager::new() {
        Ok(c) => c,
        Err(e) => { Logger::fatal(&format!("路由控制失败: {e}")); return None; }
    };
    tokio::spawn(rt_conn);
    let _ = rt_mgr.add_default_route(iface_index, WARP_TABLE).await;
    
    if let Err(e) = rt_mgr.apply_rules(
        &config.routing.must_proxy,
        &config.routing.must_bypass,
        &config.routing.rules_ips,
        config.routing.is_whitelist,
        WARP_TABLE, 0, FWMARK,
        crate::daemon::hopping::BYPASS_MARK,
    ).await {
        Logger::fatal(&format!("下发路由规则失败: {e}"));
        return None;
    }

    let prop_path = module_dir.join("module.prop");

    Logger::info("正在启动守护进程");

    let iface_str = iface.to_string();

    Some(DaemonState {
        config,
        config_path: config_path.to_string(),
        iface,
        iface_str,
        pool,
        current_endpoint: first_ep,
        hopping,
        prop_path,
        pre_disable_since: None,
        ipc_listener: Some(ipc_listener),
    })
}

pub async fn run_loop(mut state: DaemonState) {
    let hopping_interval = Duration::from_secs(state.config.hopping.interval_sec);
    let ui_interval = Duration::from_secs(state.config.info.refresh_sec);
    let mut hopping_tick = time::interval(hopping_interval);
    let mut ui_tick = time::interval(ui_interval);

    let listener = state.ipc_listener.take().expect("信道未初始化");

    let (hop_tx, mut hop_rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);

    loop {
        let endpoint_str = state.current_endpoint.to_string();
        tokio::select! {
            Some(best) = hop_rx.recv() => {
                if best != state.current_endpoint {
                    if WgManager::update_endpoint(state.iface.clone(), WARP_PEER_KEY.to_string(), best).await.is_ok() {
                        state.current_endpoint = best;
                    }
                }
            }

            result = server::handle_next(
                &listener,
                &state.iface_str,
                &state.config_path,
                &state.config,
                state.pre_disable_since,
                &endpoint_str,
                state.config.hopping.interval_sec,
            ) => {
                let (ipc_result, mut writer) = result;
                match ipc_result {
                    IpcResult::StartRequested => {
                        Logger::error("守护进程已在运行");
                    }
                    IpcResult::DeinitRequested => {
                        Logger::info("正在停用...");
                        deinit(&state).await;
                        if let Some(w) = writer.as_mut() {
                            let _ = w.write_all(b"DONE\n").await;
                        }
                        break;
                    }
                    IpcResult::ActionCompleted => {
                        if state.pre_disable_since.is_none() {
                            state.pre_disable_since = Some(Instant::now());
                            Logger::info("等待停用请求");
                        }
                    }
                    IpcResult::StatsOnly | IpcResult::Error => {}
                }
            }

            _ = hopping_tick.tick() => {
                let engine = state.hopping.clone();
                let pool = state.pool.clone();
                let concurrent = state.config.hopping.concurrent_tests;
                let tx = hop_tx.clone();
                
                tokio::spawn(async move {
                    if engine.check_connectivity().await {
                        if let Some(best_ep) = engine.find_lowest_latency(&pool, concurrent).await {
                            let _ = tx.send(best_ep).await;
                        } else {
                            Logger::warn("未发现可用端点");
                        }
                    } else {
                        Logger::warn("未连接至互联网");
                    }
                });
            }

            _ = ui_tick.tick() => {
                if let Some(since) = state.pre_disable_since {
                    if since.elapsed().as_secs() >= 5 {
                        state.pre_disable_since = None;
                        Logger::info("停用请求已过期");
                    }
                }

                if MountManager::is_safe_tmpfs(&state.prop_path).unwrap_or(false) {
                    if let Ok(stats) = WgManager::get_stats(state.iface.clone()).await {
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

async fn deinit(state: &DaemonState) {
    // 清理路由规则
    let (rt_mgr, rt_conn) = match RoutingManager::new() {
        Ok(v) => v,
        Err(e) => {
            Logger::error(&format!("无法创建路由管理器: {e}"));
            return;
        }
    };
    tokio::spawn(rt_conn);
    if let Err(e) = rt_mgr.cleanup_rules().await {
        Logger::error(&format!("清理路由失败: {e}"));
    }

    // 删除 WireGuard 接口
    let (if_mgr, if_conn) = match InterfaceManager::new() {
        Ok(v) => v,
        Err(e) => {
            Logger::error(&format!("无法创建接口管理器: {e}"));
            return;
        }
    };
    tokio::spawn(if_conn);
    match if_mgr.get_index(&state.iface_str).await {
        Ok(index) => {
            if let Err(e) = if_mgr.delete(index).await {
                Logger::error(&format!("删除接口失败: {e}"));
            } else {
                Logger::info("接口已删除");
            }
        }
        Err(_) => Logger::warn("接口不存在，跳过删除"),
    }

    let disable_path = Path::new("/data/adb/modules/WARP/disable");
    let _ = tokio::fs::write(disable_path, "").await;

    let _ = crate::prop::write_stopped(&state.prop_path).await;

    let module_dir = Path::new("/data/adb/modules/WARP");
    let _ = MountManager::cleanup_magisk_env(module_dir).await;

    let _ = tokio::fs::remove_file(server::SOCKET_PATH).await;

    Logger::info("服务已停止");
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
