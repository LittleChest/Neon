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
        let mut req = self.handle.rule().add().replace();
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

    async fn add_catch_all_rule(&self, table: u32, priority: u32) -> io::Result<()> {
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut req = self.handle.rule().add().replace();
            req.message_mut().header.family = family;
            req = req
                .table_id(table)
                .action(RuleAction::ToTable)
                .priority(priority);

            req.execute().await.map_err(|e| {
                Logger::error(&format!("无法添加 catch-all 规则 table {table}: {e}"));
                io::Error::new(io::ErrorKind::Other, e)
            })?;
        }
        Ok(())
    }

    // ip rule add fwmark <mark> goto <target> prio <priority>
    async fn add_fwmark_goto_rule(
        &self,
        mark: u32,
        mask: u32,
        priority: u32,
        target: u32,
    ) -> io::Result<()> {
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut req = self.handle.rule().add().replace();
            req.message_mut().header.family = family;
            req.message_mut().attributes.push(RuleAttribute::FwMark(mark));
            req.message_mut().attributes.push(RuleAttribute::FwMask(mask));
            req.message_mut().attributes.push(RuleAttribute::Goto(target));
            req = req.action(RuleAction::Goto).priority(priority);

            req.execute().await.map_err(|e| {
                Logger::error(&format!("无法添加 fwmark goto 规则 0x{mark:x}: {e}"));
                io::Error::new(io::ErrorKind::Other, e)
            })?;
        }
        Ok(())
    }

    // ip rule add to <cidr> goto <target> prio <priority>
    async fn add_goto_rule(&self, cidr: &IpNet, target: u32, priority: u32) -> io::Result<()> {
        let mut req = self.handle.rule().add().replace();
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
        msg.attributes.push(RouteAttribute::Destination(RouteAddress::from(dest)));
        msg.header.destination_prefix_length = prefix_len;

        self.handle.route().add(msg).replace().execute().await.map_err(|e| {
            Logger::error(&format!("无法添加路由 {dest}/{prefix_len} → table {table}: {e}"));
            io::Error::new(io::ErrorKind::Other, e)
        })
    }

    pub async fn apply_rules(
        &self,
        must_proxy: &[IpNet],
        must_bypass: &[IpNet],
        rules_ips: &[IpNet],
        is_whitelist: bool,
        table_id: u32,
        _fwmark: u32,
        _fwmask: u32,
        bypass_mark: u32,
    ) -> io::Result<()> {
        let mut count = 0;

        const PRIO_HOPPING_JUMP: u32 = 12500;
        const PRIO_MUST_PROXY: u32 = 12600;
        const PRIO_MUST_BYPASS: u32 = 14100;
        const PRIO_RULES_IPS: u32 = 14200;
        const PRIO_DEFAULT_PROXY: u32 = 14300;
        const GOTO_TARGET_SYSTEM: u32 = 15040;

        // Bypass VPN
        self.add_fwmark_goto_rule(bypass_mark, 0xffffffff, PRIO_HOPPING_JUMP, GOTO_TARGET_SYSTEM).await?;
        count += 2; // v4 + v6

        // must_proxy
        for cidr in must_proxy {
            self.add_lookup_rule(cidr, table_id, PRIO_MUST_PROXY).await?;
            count += 1;
        }

        // must_bypass
        for cidr in must_bypass {
            self.add_goto_rule(cidr, GOTO_TARGET_SYSTEM, PRIO_MUST_BYPASS).await?;
            count += 1;
        }

        // rules
        if is_whitelist {
            for cidr in rules_ips {
                self.add_lookup_rule(cidr, table_id, PRIO_RULES_IPS).await?;
                count += 1;
            }
        } else {
            for cidr in rules_ips {
                self.add_goto_rule(cidr, GOTO_TARGET_SYSTEM, PRIO_RULES_IPS).await?;
                count += 1;
            }
            
            // catch-all
            self.add_catch_all_rule(table_id, PRIO_DEFAULT_PROXY).await?;
            count += 2; // v4 + v6
        }

        Logger::info(&format!("注入了 {} 条规则", count));
        Ok(())
    }

    pub async fn cleanup_rules(&self) -> io::Result<()> {
        Logger::info("正在清理路由规则...");
        const OUR_PRIOS: &[u32] = &[12500, 12600, 14100, 14200, 14300];
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
            Logger::info(&format!("删除了 {} 条路由规则", deleted));
        }
        Ok(())
    }
}

fn set_rule_dst(req: &mut rtnetlink::RuleAddRequest, cidr: &IpNet) {
    let addr = cidr.addr();
    req.message_mut().attributes.push(RuleAttribute::Destination(addr));
    req.message_mut().header.family = if addr.is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    req.message_mut().header.dst_len = cidr.prefix_len();
    req.message_mut().header.table = 0;
}
