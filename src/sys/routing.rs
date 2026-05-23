use futures::TryStreamExt;
use crate::state::logger::Logger;
use ipnet::IpNet;
use netlink_packet_route::{
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteType},
    rule::{RuleAction, RuleAttribute},
    AddressFamily,
};
use rtnetlink::{new_connection, Handle, IpVersion};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct RoutingManager {
    handle: Handle,
}

impl RoutingManager {
    pub fn new() -> io::Result<(Self, impl std::future::Future<Output = ()>)> {
        let (connection, handle, _) = new_connection().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("无法建立 netlink 连接: {e}"))
        })?;
        Ok((Self { handle }, connection))
    }


    // ip rule add to <cidr> lookup <table> prio <priority>
    async fn add_lookup_rule(&self, cidr: &IpNet, table: u32, priority: u32) -> io::Result<()> {
        let mut req = self.handle.rule().add();
        set_rule_dst(&mut req, cidr);
        req = req
            .table_id(table)
            .action(RuleAction::ToTable)
            .priority(priority);

        req.execute().await.map_err(|e| {
            Logger::error(&format!("无法添加 lookup 规则 {cidr} → table {table}: {e}"));
            io::Error::new(io::ErrorKind::Other, e)
        })
    }

    // ip rule add fwmark <mark>/<mask> iif lo lookup <table> prio <priority>
    async fn add_fwmark_rule(
        &self,
        mark: u32,
        mask: u32,
        table: u32,
        priority: u32,
    ) -> io::Result<()> {
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut req = self.handle.rule().add();
            req.message_mut().header.family = family;
            req.message_mut()
                .attributes
                .push(RuleAttribute::FwMark(mark));
            req.message_mut()
                .attributes
                .push(RuleAttribute::FwMask(mask));
            req.message_mut()
                .attributes
                .push(RuleAttribute::Iifname("lo".to_string()));
            req = req
                .table_id(table)
                .action(RuleAction::ToTable)
                .priority(priority);

            req.execute().await.map_err(|e| {
                Logger::error(&format!("无法添加 fwmark 规则 0x{mark:x}/0x{mask:x}: {e}"));
                io::Error::new(io::ErrorKind::Other, e)
            })?;
        }
        Ok(())
    }

    // ip rule add to <cidr> goto <target> prio <priority>
    async fn add_goto_rule(&self, cidr: &IpNet, target: u32, priority: u32) -> io::Result<()> {
        let mut req = self.handle.rule().add();
        set_rule_dst(&mut req, cidr);
        req.message_mut()
            .attributes
            .push(RuleAttribute::Goto(target));
        req = req.action(RuleAction::Goto).priority(priority);

        req.execute().await.map_err(|e| {
            Logger::error(&format!("无法添加 goto 规则 {cidr} → prio {target}: {e}"));
            io::Error::new(io::ErrorKind::Other, e)
        })
    }

    // ip route add default dev <iface> table <table>
    pub async fn add_default_route(&self, iface_index: u32, table: u32) -> io::Result<()> {
        self.add_route(iface_index, table, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .await?;
        self.add_route(iface_index, table, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            .await?;
        Logger::info(&format!("默认路由已添加至: {table}"));
        Ok(())
    }

    async fn add_route(
        &self,
        oif: u32,
        table: u32,
        dest: IpAddr,
        prefix_len: u8,
    ) -> io::Result<()> {
        let family = if dest.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };

        let mut msg = RouteMessage::default();
        msg.header.address_family = family;
        msg.header.table = 0;
        msg.header.kind = RouteType::Unicast;
        msg.header.protocol = RouteProtocol::Static;
        msg.attributes.push(RouteAttribute::Table(table));
        msg.attributes.push(RouteAttribute::Oif(oif));
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::from(dest)));
        msg.header.destination_prefix_length = prefix_len;

        self.handle.route().add(msg).replace().execute().await.map_err(|e| {
            Logger::error(&format!("无法添加路由 {dest}/{prefix_len} → table {table}: {e}"));
            io::Error::new(io::ErrorKind::Other, e)
        })
    }

    //   0. Android
    //   1. must_proxy  → lookup <table>
    //   2. Android VPN
    //   3. must_bypass → goto <target>
    //   4. rules_ips
    //   5. fwmark → lookup <table> (Only blacklist mode)
    //   6. Android
    pub async fn apply_rules(
        &self,
        must_proxy: &[IpNet],
        must_bypass: &[IpNet],
        rules_ips: &[IpNet],
        is_whitelist: bool,
        table_id: u32,
        fwmark: u32,
        fwmask: u32,
    ) -> io::Result<()> {
        const PRIO_PROXY: u32 = 30500;
        const PRIO_BYPASS: u32 = 30600;
        const PRIO_LIST: u32 = 30700;
        const PRIO_FWMARK: u32 = 30999;
        const GOTO_TARGET: u32 = 31000;

        for cidr in must_proxy {
            self.add_lookup_rule(cidr, table_id, PRIO_PROXY).await?;
        }
        let n = must_proxy.len();
        if n > 0 {
            Logger::info(&format!("已注入 {n} 条强制代理规则 (prio {PRIO_PROXY})"));
        }

        for cidr in must_bypass {
            self.add_goto_rule(cidr, GOTO_TARGET, PRIO_BYPASS).await?;
        }
        let n = must_bypass.len();
        if n > 0 {
            Logger::info(&format!("已注入 {n} 条强制直连规则 (prio {PRIO_BYPASS})"));
        }

        if is_whitelist {
            for cidr in rules_ips {
                self.add_lookup_rule(cidr, table_id, PRIO_PROXY).await?;
            }
            let n = rules_ips.len();
            if n > 0 {
                Logger::info(&format!("已注入 {n} 条白名单代理规则 (prio {PRIO_PROXY})"));
            }
        } else {
            for cidr in rules_ips {
                self.add_goto_rule(cidr, GOTO_TARGET, PRIO_LIST).await?;
            }
            let n = rules_ips.len();
            if n > 0 {
                Logger::info(&format!("已注入 {n} 条黑名单直连规则 (prio {PRIO_LIST})"));
            }

            self.add_fwmark_rule(fwmark, fwmask, table_id, PRIO_FWMARK)
                .await?;
            Logger::info(&format!(
                "已注入 fwmark 规则 0x{fwmark:x}/0x{fwmask:x} (prio {PRIO_FWMARK})"
            ));
        }

        Ok(())
    }

    pub async fn cleanup_rules(&self) -> io::Result<()> {
        Logger::info("正在清理路由规则");

        const OUR_PRIOS: &[u32] = &[30500, 30600, 30700, 30999];
        let mut deleted = 0u32;

        for ip_ver in [IpVersion::V4, IpVersion::V6] {
            let mut rules = self.handle.rule().get(ip_ver).execute();
            while let Some(rule) = rules.try_next().await.map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("无法读取路由规则: {e}"))
            })? {
                let prio = rule.attributes.iter().find_map(|attr| {
                    if let RuleAttribute::Priority(p) = attr { Some(*p) } else { None }
                });
                if let Some(prio) = prio {
                    if OUR_PRIOS.contains(&prio) {
                        if let Err(e) = self.handle.rule().del(rule).execute().await {
                            Logger::error(&format!("无法删除规则 prio {prio}: {e}"));
                        } else {
                            deleted += 1;
                        }
                    }
                }
            }
        }

        if deleted > 0 {
            Logger::info(&format!("已清理 {deleted} 条路由规则"));
        }
        Ok(())
    }
}

fn set_rule_dst(req: &mut rtnetlink::RuleAddRequest, cidr: &IpNet) {
    let addr = cidr.addr();
    req.message_mut()
        .attributes
        .push(RuleAttribute::Destination(addr));
    req.message_mut().header.family = if addr.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    req.message_mut().header.dst_len = cidr.prefix_len();
    req.message_mut().header.table = 0;
}

