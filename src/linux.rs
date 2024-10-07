// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::str;
use std::{io::Error, mem, net::IpAddr, ptr, slice};

use libc::{
    c_int, c_uchar, c_uint, c_ushort, close, nlmsghdr, recv, socket, write, AF_INET, AF_INET6,
    AF_NETLINK, AF_UNSPEC, ARPHRD_NONE, IFLA_IFNAME, IFLA_MTU, MSG_DONTWAIT, NETLINK_ROUTE,
    NLM_F_ACK, NLM_F_REQUEST, RTA_DST, RTA_OIF, RTM_GETLINK, RTM_GETROUTE, RTM_NEWLINK,
    RTM_NEWROUTE, RTN_UNICAST, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN, SOCK_RAW,
};

use crate::{default_err, next_item_aligned_by_four};

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct ifinfomsg {
    ifi_family: c_uchar, // AF_UNSPEC
    ifi_type: c_ushort,  // Device type
    ifi_index: c_int,    // Interface index
    ifi_flags: c_uint,   // Device flags
    ifi_change: c_uint,  // change mask
}

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct rtmsg {
    rtm_family: c_uchar,   // Address family of route
    rtm_dst_len: c_uchar,  // Length of destination
    rtm_src_len: c_uchar,  // Length of source
    rtm_tos: c_uchar,      // TOS filter
    rtm_table: c_uchar,    // Routing table ID; see RTA_TABLE below
    rtm_protocol: c_uchar, // Routing protocol; see below
    rtm_scope: c_uchar,    // See below
    rtm_type: c_uchar,     // See below
    rtm_flags: c_uint,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct rtattr {
    rta_len: c_ushort,  // Length of option
    rta_type: c_ushort, // Type of option
} // Data follows

const fn addr_len(remote: &IpAddr) -> u8 {
    match remote {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn addr_bytes(remote: &IpAddr) -> Vec<u8> {
    match remote {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn prepare_nlmsg(nl_type: c_ushort, nl_len: usize, nl_seq: u32) -> nlmsghdr {
    nlmsghdr {
        nlmsg_len: nl_len.try_into().map_err(|_| default_err()).unwrap(),
        nlmsg_type: nl_type,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK)
            .try_into()
            .map_err(|_| default_err())
            .unwrap(),
        nlmsg_seq: nl_seq,
        nlmsg_pid: 0,
    }
}

fn if_index(remote: IpAddr, fd: i32) -> Result<i32, Error> {
    // Prepare RTM_GETROUTE message.
    let nl_msglen = mem::size_of::<nlmsghdr>()
        + mem::size_of::<rtmsg>()
        + mem::size_of::<rtattr>()
        + addr_bytes(&remote).len();
    let nl_hdr = prepare_nlmsg(RTM_GETROUTE, nl_msglen, 0);

    let rt_msg = rtmsg {
        rtm_family: match remote {
            IpAddr::V4(_) => AF_INET.try_into().map_err(|_| default_err())?,
            IpAddr::V6(_) => AF_INET6.try_into().map_err(|_| default_err())?,
        },
        rtm_dst_len: addr_len(&remote),
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: 0,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };

    let rt_attr = rtattr {
        rta_len: (mem::size_of::<rtattr>() + addr_bytes(&remote).len())
            .try_into()
            .map_err(|_| default_err())?,
        rta_type: RTA_DST,
    };

    let mut buffer = vec![0u8; nl_msglen];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&nl_hdr).cast(),
            buffer.as_mut_ptr(),
            mem::size_of::<nlmsghdr>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&rt_msg).cast(),
            buffer.as_mut_ptr().add(mem::size_of::<nlmsghdr>()),
            mem::size_of::<rtmsg>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&rt_attr).cast(),
            buffer
                .as_mut_ptr()
                .add(mem::size_of::<nlmsghdr>() + mem::size_of::<rtmsg>()),
            mem::size_of::<rtattr>(),
        );
        ptr::copy_nonoverlapping(
            addr_bytes(&remote).as_ptr(),
            buffer.as_mut_ptr().add(
                mem::size_of::<nlmsghdr>() + mem::size_of::<rtmsg>() + mem::size_of::<rtattr>(),
            ),
            addr_bytes(&remote).len(),
        );
    };

    // Send RTM_GETROUTE message to get the interfce index associated with the destination.
    if unsafe { write(fd, buffer.as_ptr().cast(), buffer.len()) } < 0 {
        let err = Error::last_os_error();
        unsafe { close(fd) };
        return Err(err);
    }

    // Receive RTM_GETROUTE response.
    loop {
        let mut recv_buf = vec![0u8; 4096];
        let recv_len = unsafe {
            recv(
                fd,
                recv_buf.as_mut_ptr().cast(),
                recv_buf.len(),
                MSG_DONTWAIT,
            )
        };
        if recv_len <= 0 {
            return Err(Error::last_os_error());
        }

        let mut offset = 0;
        while offset < recv_len.try_into().map_err(|_| default_err())? {
            let hdr =
                unsafe { ptr::read_unaligned(recv_buf.as_ptr().add(offset).cast::<nlmsghdr>()) };
            if hdr.nlmsg_seq == 0 && hdr.nlmsg_type == RTM_NEWROUTE {
                let mut attr_ptr = unsafe {
                    recv_buf
                        .as_ptr()
                        .add(offset + mem::size_of::<nlmsghdr>() + mem::size_of::<rtmsg>())
                };
                let attr_end = unsafe { recv_buf.as_ptr().add(offset + hdr.nlmsg_len as usize) };
                while attr_ptr < attr_end {
                    let attr = unsafe { ptr::read_unaligned(attr_ptr.cast::<rtattr>()) };
                    if attr.rta_type == RTA_OIF {
                        let idx = unsafe {
                            ptr::read_unaligned(
                                attr_ptr.add(mem::size_of::<rtattr>()).cast::<i32>(),
                            )
                        };
                        return Ok(idx);
                    }
                    attr_ptr = unsafe { attr_ptr.add(attr.rta_len as usize) };
                }
            }
            offset += hdr.nlmsg_len as usize;
        }
    }
}

fn if_name_mtu(if_index: i32, fd: i32) -> Result<(String, usize), Error> {
    // Prepare RTM_GETLINK message to get the interface name and MTU for the interface with the
    // obtained index.

    let nl_msglen = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
    let nl_hdr = prepare_nlmsg(RTM_GETLINK, nl_msglen, 1);

    let if_info_msg = ifinfomsg {
        ifi_family: AF_UNSPEC.try_into().map_err(|_| default_err())?,
        ifi_type: ARPHRD_NONE,
        ifi_index: if_index,
        ifi_flags: 0,
        ifi_change: 0,
    };

    let mut buffer = vec![0u8; nl_msglen];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&nl_hdr).cast(),
            buffer.as_mut_ptr(),
            mem::size_of::<nlmsghdr>(),
        );
        ptr::copy_nonoverlapping(
            std::ptr::from_ref(&if_info_msg).cast(),
            buffer.as_mut_ptr().add(mem::size_of::<nlmsghdr>()),
            mem::size_of::<ifinfomsg>(),
        );
    }

    // Send RTM_GETLINK message.
    if unsafe { write(fd, buffer.as_ptr().cast(), buffer.len()) } < 0 {
        let err = Error::last_os_error();
        unsafe { close(fd) };
        return Err(err);
    }

    // Receive RTM_GETLINK response.
    let mut ifname = None;
    let mut mtu = None;
    'recv: loop {
        let mut recv_buf = vec![0u8; 4096];
        let recv_len = unsafe {
            recv(
                fd,
                recv_buf.as_mut_ptr().cast(),
                recv_buf.len(),
                MSG_DONTWAIT,
            )
        };
        if recv_len <= 0 {
            return Err(Error::last_os_error());
        }

        let mut offset = 0;
        while offset < recv_len.try_into().map_err(|_| default_err())? {
            let hdr =
                unsafe { ptr::read_unaligned(recv_buf.as_ptr().add(offset).cast::<nlmsghdr>()) };
            if hdr.nlmsg_seq == 1 && hdr.nlmsg_type == RTM_NEWLINK {
                let mut attr_ptr = unsafe {
                    recv_buf
                        .as_ptr()
                        .add(offset + mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>())
                };
                let attr_end = unsafe { recv_buf.as_ptr().add(offset + hdr.nlmsg_len as usize) };

                while attr_ptr < attr_end {
                    let attr = unsafe { ptr::read_unaligned(attr_ptr.cast::<rtattr>()) };
                    if attr.rta_type == IFLA_IFNAME {
                        let name = unsafe {
                            slice::from_raw_parts(
                                attr_ptr.add(mem::size_of::<rtattr>()),
                                attr.rta_len as usize - mem::size_of::<rtattr>() - 1,
                            )
                        };
                        if let Ok(name) = str::from_utf8(name) {
                            // We have our interface name.
                            ifname = Some(name.to_string());
                        }
                    } else if attr.rta_type == IFLA_MTU {
                        mtu = Some(
                            unsafe {
                                ptr::read_unaligned(
                                    attr_ptr.add(mem::size_of::<rtattr>()).cast::<i32>(),
                                )
                            }
                            .try_into()
                            .map_err(|_| default_err())?,
                        );
                    }

                    let incr = next_item_aligned_by_four(attr.rta_len as usize);
                    attr_ptr = unsafe { attr_ptr.add(incr) };
                }
                if ifname.is_some() && mtu.is_some() {
                    break 'recv;
                }
            }
            offset += hdr.nlmsg_len as usize;
        }
    }

    let ifname =
        ifname.ok_or_else(|| Error::new(std::io::ErrorKind::Other, "Interface name not found"))?;
    let mtu = mtu.ok_or_else(|| Error::new(std::io::ErrorKind::Other, "MTU not found"))?;

    Ok((ifname, mtu))
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Create a netlink socket.
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }

    let if_index = if_index(remote, fd)?;
    let res = if_name_mtu(if_index, fd);
    unsafe { close(fd) };
    res
}
