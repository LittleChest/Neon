use futures::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use rtnetlink::{new_connection, Handle};
use std::io;

pub struct InterfaceManager {
    handle: Handle,
}

impl InterfaceManager {
    pub fn new() -> io::Result<(Self, impl std::future::Future<Output = ()>)> {
        let (connection, handle, _) = new_connection().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("无法与内核通信: {e}"),
            )
        })?;
        Ok((Self { handle }, connection))
    }

    pub async fn create_wg(&self, name: &str, mtu: u32) -> io::Result<u32> {
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::empty();
        msg.header.change_mask = LinkFlags::empty();

        msg.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        msg.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Wireguard,
            )]));
        msg.attributes.push(LinkAttribute::Mtu(mtu));

        self.handle
            .link()
            .add(msg)
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("无法创建网卡 {name}: {e}")))?;

        self.get_index(name).await
    }

    pub async fn set_up(&self, index: u32) -> io::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        self.handle
            .link()
            .change(msg)
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("无法启用网卡: {e}")))
    }

    pub async fn add_ip(&self, index: u32, ip: &IpNet) -> io::Result<()> {
        self.handle
            .address()
            .add(index, ip.addr(), ip.prefix_len())
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("无法分配 IP {ip}: {e}")))
    }

    pub async fn delete(&self, index: u32) -> io::Result<()> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("无法删除网卡: {e}")))
    }

    pub async fn get_index(&self, name: &str) -> io::Result<u32> {
        let mut stream = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        if let Some(link) = stream
            .try_next()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("无法查询网卡: {e}")))?
        {
            Ok(link.header.index)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("找不到接口: {name}"),
            ))
        }
    }
}
