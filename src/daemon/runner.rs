use crate::config::Config;
use crate::daemon::hopping::{decode_b64_key, HoppingEngine};
use crate::ipc::SOCKET_PATH;
use crate::state::logger::Logger;
use crate::state::ui::UiRenderer;
use crate::sys::interface::InterfaceManager;
use crate::sys::mount::MountManager;
use crate::sys::routing::RoutingManager;
use crate::sys::wg::WgManager;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::time;
use wireguard_control::InterfaceName;
use futures::StreamExt;
use inotify::{Inotify, WatchMask};

pub const WARP_PEER_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
pub const WARP_IP_BASE: [u8; 4] = [162, 159, 193, 1];
pub const WARP_IP_COUNT: u8 = 10;
const FWMARK: u32 = 0x20000;
const WARP_TABLE: u32 = 0x20000;

pub const WARP_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
    955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
    7559, 8319, 8742, 8854, 8886,
];

pub struct DaemonState {
    pub config: Config,
    pub iface: InterfaceName,
    pub iface_str: String,
    pub pool: Vec<SocketAddr>,
    pub current_endpoint: SocketAddr,
    pub hopping: std::sync::Arc<HoppingEngine>,
    pub prop_path: PathBuf,
}

pub async fn run_daemon(config_path: &str) {
    let config = Config::load_and_verify(config_path).await.unwrap_or_default();
    let module_dir = Path::new("/data/adb/modules/WARP");
    let tmp_dir = Path::new("/dev/warp");
    let dev_prop_path = Path::new("/dev/warp/module.prop");
    let disable_path = Path::new("/data/adb/modules/WARP/disable");

    if config.info.allow_mount {
        let _ = MountManager::setup_magisk_env(module_dir, &[tmp_dir]).await;
    }

    Logger::init(crate::LOG_FILE);

    let inotify = Inotify::init().expect("Failed to init inotify");
    inotify.watches().add("/data/adb/modules/WARP", WatchMask::CREATE | WatchMask::DELETE).expect("Failed to add watch");
    let mut notify_stream = inotify.into_event_stream([0u8; 1024]).expect("Failed to create inotify stream");

    let _ = tokio::fs::remove_file(SOCKET_PATH).await;
    if let Some(parent) = Path::new(SOCKET_PATH).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let ipc_listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            Logger::error(&format!("无法绑定套接字: {e}"));
            return;
        }
    };

    loop {
        if disable_path.exists() {
            tokio::select! {
                Some(_) = notify_stream.next() => {}
                Ok((mut stream, _)) = ipc_listener.accept() => {
                    let mut buf = [0u8; 32];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        if msg.trim() == "ping" {
                            let _ = stream.write_all(b"PONG\n").await;
                        }
                    }
                }
            }
            continue;
        }

        Logger::info("载入中...");
        
        if config.info.allow_mount {
            UiRenderer::update_prop_status(dev_prop_path, "✅ 正在启用 | ", config.info.allow_mount).await;
        }

        if let Some(mut state) = init(config.clone()).await {
            run_loop(&mut state, disable_path, &ipc_listener, &mut notify_stream).await;
            deinit(&state).await;
        } else {
            Logger::error("初始化失败...");
            emergency_cleanup(module_dir, &config).await;
            return;
        }
    }
}

pub async fn init(config: Config) -> Option<DaemonState> {
    let pool = build_endpoint_pool();
    let dev_prop_path = Path::new("/dev/warp/module.prop");
    
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

    Logger::info("正在启动守护进程");

    Some(DaemonState {
        config,
        iface,
        iface_str: iface_name,
        pool,
        current_endpoint: first_ep,
        hopping,
        prop_path: dev_prop_path.to_path_buf(),
    })
}

pub async fn run_loop(
    state: &mut DaemonState, 
    disable_path: &Path, 
    ipc_listener: &UnixListener, 
    notify_stream: &mut inotify::EventStream<[u8; 1024]>
) {
    let hopping_interval = Duration::from_secs(state.config.hopping.interval_sec);
    let ui_interval = Duration::from_secs(state.config.info.refresh_sec);
    let mut hopping_tick = time::interval(hopping_interval);
    let mut ui_tick = time::interval(ui_interval);

    let (hop_tx, mut hop_rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);

    loop {
        tokio::select! {
            Some(_) = notify_stream.next() => {
                if disable_path.exists() {
                    break;
                }
            }

            Some(best) = hop_rx.recv() => {
                if best != state.current_endpoint {
                    if WgManager::update_endpoint(state.iface.clone(), WARP_PEER_KEY.to_string(), best).await.is_ok() {
                        state.current_endpoint = best;
                    }
                }
            }

            Ok((mut stream, _)) = ipc_listener.accept() => {
                let mut buf = [0u8; 32];
                if let Ok(n) = stream.read(&mut buf).await {
                    let msg = String::from_utf8_lossy(&buf[..n]);
                    match msg.trim() {
                        "ping" => {
                            let _ = stream.write_all(b"PONG\n").await;
                        }
                        "mark_read" => {
                            Logger::reset_counters();
                            let _ = stream.write_all(b"OK\n").await;
                        }
                        _ => {}
                    }
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
                if !state.config.info.allow_mount || MountManager::is_safe_tmpfs(&state.prop_path).unwrap_or(false) {
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
                            state.config.info.allow_mount
                        ).await;
                    }
                }
            }
        }
    }
}

async fn deinit(state: &DaemonState) {
    UiRenderer::update_prop_status(&state.prop_path, "❌ 正在停用 | ", state.config.info.allow_mount).await;

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

    if state.config.info.allow_mount {
        let _ = crate::prop::write_stopped(&state.prop_path).await;
        let module_dir = Path::new("/data/adb/modules/WARP");
        let _ = MountManager::cleanup_magisk_env(module_dir).await;
    }

    Logger::info("服务已停止");
}

async fn emergency_cleanup(module_dir: &Path, config: &Config) {
    if config.info.allow_mount {
        let _ = MountManager::cleanup_magisk_env(module_dir).await;
    }
    if let Ok((rt_mgr, rt_conn)) = RoutingManager::new() {
        tokio::spawn(rt_conn);
        let _ = rt_mgr.cleanup_rules().await;
    }
    if let Ok((if_mgr, if_conn)) = InterfaceManager::new() {
        tokio::spawn(if_conn);
        for i in 0..100 {
            let name = if i == 0 { "warp".to_string() } else { format!("warp{}", i - 1) };
            if let Ok(index) = if_mgr.get_index(&name).await {
                let _ = if_mgr.delete(index).await;
            }
        }
    }
    let _ = tokio::fs::remove_file(crate::ipc::SOCKET_PATH).await;
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
