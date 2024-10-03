// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{io::Error, net::IpAddr};

use neli::{
    attr::Attribute,
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{
            Arphrd, IffFlags, Ifla, RtAddrFamily, RtScope, RtTable, Rta, Rtm, RtmFFlags, Rtn,
            Rtprot,
        },
        socket::NlFamily,
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifinfomsg, Rtattr, Rtmsg},
    socket::NlSocketHandle,
    types::RtBuffer,
};

use crate::default_err;

const fn family(remote: &IpAddr) -> RtAddrFamily {
    if remote.is_ipv4() {
        RtAddrFamily::Inet
    } else {
        RtAddrFamily::Inet6
    }
}

const fn addr_len(remote: &IpAddr) -> u8 {
    if remote.is_ipv4() {
        32
    } else {
        128
    }
}

fn addr_bytes(remote: &IpAddr) -> Vec<u8> {
    match remote {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Create a netlink socket.
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;

    // Send RTM_GETROUTE message to retrieve the route for the destination IP.
    let mut route_msg = Rtmsg {
        rtm_family: family(&remote),
        rtm_dst_len: addr_len(&remote),
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Default,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unicast,
        rtm_flags: RtmFFlags::empty(),
        rtattrs: RtBuffer::new(),
    };
    let rta = Rtattr::new(None, Rta::Dst, addr_bytes(&remote)).map_err(|_| default_err())?;
    route_msg.rtattrs.push(rta);
    let route_request = Nlmsghdr::new(
        None,
        Rtm::Getroute,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(route_msg),
    );
    socket.send(route_request).or(Err(default_err()))?;

    // Receive all response to RTM_GETROUTE. (If we don't consume all responses, it seems like we
    // cannot reuse it for another request.)
    let mut ifindex = None;
    for response in socket.iter(false) {
        let header: Nlmsghdr<Rtm, Rtmsg> = response.map_err(|_| default_err())?;
        if header.nl_type != Rtm::Newroute {
            continue;
        }
        let route_attrs = &header.get_payload().map_err(|_| default_err())?.rtattrs;
        for attr in route_attrs.iter() {
            if let Ok(index) = attr.get_payload_as::<i32>() {
                if attr.rta_type == Rta::Oif {
                    ifindex = Some(index);
                    break;
                }
            }
        }
    }
    let ifindex = ifindex.ok_or_else(default_err)?;

    // Send RTM_GETLINK message to retrieve the interface details.
    let link_msg = Ifinfomsg::new(
        family(&remote),
        Arphrd::None,
        ifindex as libc::c_int,
        IffFlags::empty(),
        IffFlags::empty(),
        RtBuffer::new(),
    );
    let link_request = Nlmsghdr::new(
        None,
        Rtm::Getlink,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(link_msg),
    );
    socket.send(link_request).or(Err(default_err()))?;

    // Receive the responses to RTM_GETLINK.
    let mut ifname = None;
    let mut mtu = None;
    for response in socket.iter(false) {
        let header: Nlmsghdr<Rtm, Ifinfomsg> = response.map_err(|_| default_err())?;
        if header.nl_type != Rtm::Newlink {
            continue;
        }
        let link_attrs = &header.get_payload().map_err(|_| default_err())?.rtattrs;
        for attr in link_attrs.iter() {
            if attr.rta_type == Ifla::Ifname {
                if let Ok(name) = attr.get_payload_as_with_len::<String>() {
                    ifname = Some(name);
                }
            } else if attr.rta_type == Ifla::Mtu {
                if let Ok(mtu_val) = attr.get_payload_as::<u32>() {
                    mtu = Some(mtu_val as usize);
                }
            }
        }
    }
    let ifname = ifname.ok_or_else(default_err)?;
    let mtu = mtu.ok_or_else(default_err)?;

    Ok((ifname, mtu))
}
