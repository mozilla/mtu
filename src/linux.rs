// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ffi::CStr,
    io::{Error, ErrorKind, Read, Write},
    mem::size_of,
    net::IpAddr,
    num::TryFromIntError,
    ptr, slice,
};

use libc::{
    c_int, AF_INET, AF_INET6, AF_NETLINK, AF_UNSPEC, ARPHRD_NONE, IFLA_IFNAME, IFLA_MTU,
    NETLINK_ROUTE, NLMSG_ERROR, NLM_F_ACK, NLM_F_REQUEST, RTA_DST, RTA_OIF, RTM_GETLINK,
    RTM_GETROUTE, RTM_NEWLINK, RTM_NEWROUTE, RTN_UNICAST, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};
use static_assertions::{const_assert, const_assert_eq};

use crate::{aligned_by, default_err, routesocket::RouteSocket, unlikely_err};

#[allow(
    clippy::struct_field_names,
    non_camel_case_types,
    clippy::too_many_lines
)]
mod bindings {
    include!(env!("BINDINGS"));
}

use bindings::{ifinfomsg, nlmsghdr, rtattr, rtmsg};

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_INET_U8: u8 = AF_INET as u8;
const_assert_eq!(AF_INET_U8 as i32, AF_INET);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_INET6_U8: u8 = AF_INET6 as u8;
const_assert_eq!(AF_INET6_U8 as i32, AF_INET6);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_UNSPEC_U8: u8 = AF_UNSPEC as u8;
const_assert_eq!(AF_UNSPEC_U8 as i32, AF_UNSPEC);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const NLM_F_REQUEST_U16: u16 = NLM_F_REQUEST as u16;
const_assert_eq!(NLM_F_REQUEST_U16 as c_int, NLM_F_REQUEST);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const NLM_F_ACK_U16: u16 = NLM_F_ACK as u16;
const_assert_eq!(NLM_F_ACK_U16 as c_int, NLM_F_ACK);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const NLMSG_ERROR_U16: u16 = NLMSG_ERROR as u16;
const_assert_eq!(NLMSG_ERROR_U16 as c_int, NLMSG_ERROR);

const_assert!(size_of::<nlmsghdr>() <= u8::MAX as usize);
const_assert!(size_of::<rtmsg>() <= u8::MAX as usize);
const_assert!(size_of::<rtattr>() <= u8::MAX as usize);
const_assert!(size_of::<ifinfomsg>() <= u8::MAX as usize);

const NETLINK_BUFFER_SIZE: usize = 8192; // See netlink(7) man page.

#[repr(C)]
enum AddrBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl AddrBytes {
    const fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => Self::V6(ip.octets()),
        }
    }

    const fn len(&self) -> usize {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 16,
        }
    }
}

impl From<AddrBytes> for [u8; 16] {
    fn from(addr: AddrBytes) -> Self {
        match addr {
            AddrBytes::V4(bytes) => {
                let mut v6 = [0; 16];
                v6[..4].copy_from_slice(&bytes);
                v6
            }
            AddrBytes::V6(bytes) => bytes,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct IfIndexMsg {
    nlmsg: nlmsghdr,
    rtm: rtmsg,
    rt: rtattr,
    addr: [u8; 16],
}

impl IfIndexMsg {
    fn new(remote: IpAddr, nlmsg_seq: u32) -> Self {
        let addr = AddrBytes::new(remote);
        #[allow(clippy::cast_possible_truncation)]
        // Structs lens are <= u8::MAX per `const_assert!`s above; `addr_bytes` is max. 16 for IPv6.
        let nlmsg_len =
            (size_of::<nlmsghdr>() + size_of::<rtmsg>() + size_of::<rtattr>() + addr.len()) as u32;
        Self {
            nlmsg: nlmsghdr {
                nlmsg_len,
                nlmsg_type: RTM_GETROUTE,
                nlmsg_flags: NLM_F_REQUEST_U16 | NLM_F_ACK_U16,
                nlmsg_seq,
                ..Default::default()
            },
            rtm: rtmsg {
                rtm_family: match remote {
                    IpAddr::V4(_) => AF_INET_U8,
                    IpAddr::V6(_) => AF_INET6_U8,
                },
                rtm_dst_len: match remote {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                },
                rtm_table: RT_TABLE_MAIN,
                rtm_scope: RT_SCOPE_UNIVERSE,
                rtm_type: RTN_UNICAST,
                ..Default::default()
            },
            rt: rtattr {
                #[allow(clippy::cast_possible_truncation)]
                // Structs len is <= u8::MAX per `const_assert!` above; `addr_bytes` is max. 16 for IPv6.
                rta_len: (size_of::<rtattr>() + addr.len()) as u16,
                rta_type: RTA_DST,
            },
            addr: addr.into(),
        }
    }

    const fn len(&self) -> usize {
        let len = self.nlmsg.nlmsg_len as usize;
        debug_assert!(len <= size_of::<Self>());
        len
    }

    const fn seq(&self) -> u32 {
        self.nlmsg.nlmsg_seq
    }
}

impl From<&IfIndexMsg> for &[u8] {
    fn from(value: &IfIndexMsg) -> Self {
        unsafe { slice::from_raw_parts(ptr::from_ref(value).cast(), value.len()) }
    }
}

impl TryFrom<&[u8]> for nlmsghdr {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < size_of::<Self>() {
            return Err(default_err());
        }
        Ok(unsafe { ptr::read_unaligned(value.as_ptr().cast()) })
    }
}

fn parse_c_int(buf: &[u8]) -> Result<c_int, Error> {
    if buf.len() < size_of::<c_int>() {
        return Err(default_err());
    }
    let bytes = &buf[..size_of::<c_int>()];
    let i = c_int::from_ne_bytes(bytes.try_into().map_err(|_| default_err())?);
    Ok(i)
}

fn read_msg_with_seq(
    fd: &mut RouteSocket,
    seq: u32,
    kind: u16,
) -> Result<(nlmsghdr, Vec<u8>), Error> {
    loop {
        let buf = &mut [0u8; NETLINK_BUFFER_SIZE];
        let len = fd.read(buf.as_mut_slice())?;
        let mut next = &buf[..len];
        while size_of::<nlmsghdr>() <= next.len() {
            let (hdr, mut msg) = next.split_at(size_of::<nlmsghdr>());
            let hdr: nlmsghdr = hdr.try_into()?;
            // `msg` has the remainder of this message plus any following messages.
            // Strip those it off and assign them to `next`.
            debug_assert!(size_of::<nlmsghdr>() <= hdr.nlmsg_len as usize);
            (msg, next) = msg.split_at(hdr.nlmsg_len as usize - size_of::<nlmsghdr>());

            if hdr.nlmsg_seq != seq {
                continue;
            }

            if hdr.nlmsg_type == NLMSG_ERROR_U16 {
                // Extract the error code and return it.
                let err = parse_c_int(msg)?;
                if err != 0 {
                    return Err(Error::from_raw_os_error(-err));
                }
            } else if hdr.nlmsg_type == kind {
                // Return the header and the message.
                return Ok((hdr, msg.to_vec()));
            }
        }
    }
}

impl TryFrom<&[u8]> for rtattr {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < size_of::<Self>() {
            return Err(default_err());
        }
        Ok(unsafe { ptr::read_unaligned(value.as_ptr().cast()) })
    }
}

struct RtAttr<'a> {
    hdr: rtattr,
    msg: &'a [u8],
}

impl<'a> RtAttr<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        debug_assert!(bytes.len() >= size_of::<rtattr>());
        let (hdr, mut msg) = bytes.split_at(size_of::<rtattr>());
        let hdr: rtattr = hdr.try_into()?;
        let aligned_len = aligned_by(hdr.rta_len.into(), 4);
        debug_assert!(size_of::<rtattr>() <= aligned_len);
        (msg, _) = msg.split_at(aligned_len - size_of::<rtattr>());
        Ok(Self { hdr, msg })
    }
}

struct RtAttrs<'a>(&'a [u8]);

impl<'a> Iterator for RtAttrs<'a> {
    type Item = RtAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if size_of::<rtattr>() <= self.0.len() {
            let attr = RtAttr::new(self.0).ok()?;
            let aligned_len = aligned_by(attr.hdr.rta_len.into(), 4);
            debug_assert!(self.0.len() >= aligned_len);
            self.0 = self.0.split_at(aligned_len).1;
            Some(attr)
        } else {
            None
        }
    }
}

fn if_index(remote: IpAddr, fd: &mut RouteSocket) -> Result<i32, Error> {
    // Send RTM_GETROUTE message to get the interface index associated with the destination.
    let msg = &IfIndexMsg::new(remote, 1);
    let msg_seq = msg.seq();
    fd.write_all(msg.into())?;

    // Receive RTM_GETROUTE response.
    let (_hdr, mut buf) = read_msg_with_seq(fd, msg_seq, RTM_NEWROUTE)?;
    debug_assert!(size_of::<rtmsg>() <= buf.len());
    let buf = buf.split_off(size_of::<rtmsg>());

    // Parse through the attributes to find the interface index.
    for attr in RtAttrs(buf.as_slice()).by_ref() {
        if attr.hdr.rta_type == RTA_OIF {
            // We have our interface index.
            return parse_c_int(attr.msg);
        }
    }
    Err(default_err())
}

#[repr(C)]
struct IfInfoMsg {
    nlmsg: nlmsghdr,
    ifim: ifinfomsg,
}

impl IfInfoMsg {
    fn new(if_index: i32, nlmsg_seq: u32) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        // Structs lens are <= u8::MAX per `const_assert!`s above.
        let nlmsg_len = (size_of::<nlmsghdr>() + size_of::<ifinfomsg>()) as u32;
        Self {
            nlmsg: nlmsghdr {
                nlmsg_len,
                nlmsg_type: RTM_GETLINK,
                nlmsg_flags: NLM_F_REQUEST_U16 | NLM_F_ACK_U16,
                nlmsg_seq,
                ..Default::default()
            },
            ifim: ifinfomsg {
                ifi_family: AF_UNSPEC_U8,
                ifi_type: ARPHRD_NONE,
                ifi_index: if_index,
                ..Default::default()
            },
        }
    }

    const fn len(&self) -> usize {
        self.nlmsg.nlmsg_len as usize
    }

    const fn seq(&self) -> u32 {
        self.nlmsg.nlmsg_seq
    }
}

impl From<&IfInfoMsg> for &[u8] {
    fn from(value: &IfInfoMsg) -> Self {
        debug_assert!(value.len() >= size_of::<Self>());
        unsafe { slice::from_raw_parts(ptr::from_ref(value).cast(), value.len()) }
    }
}

fn if_name_mtu(if_index: i32, fd: &mut RouteSocket) -> Result<(String, usize), Error> {
    // Send RTM_GETLINK message to get interface information for the given interface index.
    let msg = &IfInfoMsg::new(if_index, 2);
    let msg_seq = msg.seq();
    fd.write_all(msg.into())?;

    // Receive RTM_GETLINK response.
    let (_hdr, mut buf) = read_msg_with_seq(fd, msg_seq, RTM_NEWLINK)?;
    debug_assert!(size_of::<ifinfomsg>() <= buf.len());
    let buf = buf.split_off(size_of::<ifinfomsg>());

    // Parse through the attributes to find the interface name and MTU.
    let mut ifname = None;
    let mut mtu = None;
    for attr in RtAttrs(buf.as_slice()).by_ref() {
        match attr.hdr.rta_type {
            IFLA_IFNAME => {
                let name = CStr::from_bytes_until_nul(attr.msg)
                    .map_err(|err| Error::new(ErrorKind::Other, err))?;
                ifname = Some(
                    name.to_str()
                        .map_err(|err| Error::new(ErrorKind::Other, err))?
                        .to_string(),
                );
            }
            IFLA_MTU => {
                mtu = Some(
                    parse_c_int(attr.msg)?
                        .try_into()
                        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?,
                );
            }
            _ => (),
        }
        if let (Some(ifname), Some(mtu)) = (ifname.as_ref(), mtu.as_ref()) {
            return Ok((ifname.clone(), *mtu));
        }
    }

    Err(default_err())
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Create a netlink socket.
    let mut fd = RouteSocket::new(AF_NETLINK, NETLINK_ROUTE)?;
    let if_index = if_index(remote, &mut fd)?;
    if_name_mtu(if_index, &mut fd)
}
