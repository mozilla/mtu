// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ffi::CStr,
    io::Error,
    mem::{size_of, zeroed},
    net::IpAddr,
    num::TryFromIntError,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    ptr,
};

use libc::{
    c_int, c_uchar, c_uint, c_ushort, nlmsghdr, recv, socket, write, AF_INET, AF_INET6, AF_NETLINK,
    AF_UNSPEC, ARPHRD_NONE, IFLA_IFNAME, IFLA_MTU, NETLINK_ROUTE, NLM_F_ACK, NLM_F_REQUEST,
    RTA_DST, RTA_OIF, RTM_GETLINK, RTM_GETROUTE, RTM_NEWLINK, RTM_NEWROUTE, RTN_UNICAST,
    RT_SCOPE_UNIVERSE, RT_TABLE_MAIN, SOCK_RAW,
};
use static_assertions::{const_assert, const_assert_eq};

use crate::{aligned_by, default_err, unlikely_err};

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

const_assert!(size_of::<nlmsghdr>() <= u8::MAX as usize);
const_assert!(size_of::<rtmsg>() <= u8::MAX as usize);
const_assert!(size_of::<rtattr>() <= u8::MAX as usize);
const_assert!(size_of::<ifinfomsg>() <= u8::MAX as usize);

const NETLINK_BUFFER_SIZE: usize = 8192; // See netlink(7) man page.

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

const fn prepare_nlmsg(nlmsg_type: c_ushort, nlmsg_len: u32, nlmsg_seq: u32) -> libc::nlmsghdr {
    let mut nlm = unsafe { zeroed::<nlmsghdr>() };
    nlm.nlmsg_len = nlmsg_len;
    nlm.nlmsg_type = nlmsg_type;
    nlm.nlmsg_flags = NLM_F_REQUEST_U16 | NLM_F_ACK_U16;
    nlm.nlmsg_seq = nlmsg_seq;
    nlm
}

fn if_index(remote: IpAddr, fd: BorrowedFd) -> Result<i32, Error> {
    // Prepare RTM_GETROUTE message.
    #[allow(clippy::cast_possible_truncation)]
    // Structs lens are <= u8::MAX per `const_assert!`s above; `addr_bytes` is max. 16 for IPv6.
    let nlmsg_len = (size_of::<nlmsghdr>()
        + size_of::<rtmsg>()
        + size_of::<rtattr>()
        + addr_bytes(&remote).len()) as u32;
    let nlmsg_seq = 1;
    let hdr = prepare_nlmsg(RTM_GETROUTE, nlmsg_len, nlmsg_seq);

    let mut rtm = unsafe { zeroed::<rtmsg>() };
    rtm.rtm_family = match remote {
        IpAddr::V4(_) => AF_INET_U8,
        IpAddr::V6(_) => AF_INET6_U8,
    };
    rtm.rtm_dst_len = addr_len(&remote);
    rtm.rtm_table = RT_TABLE_MAIN;
    rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    rtm.rtm_type = RTN_UNICAST;

    let mut attr = unsafe { zeroed::<rtattr>() };
    #[allow(clippy::cast_possible_truncation)]
    // Structs len is <= u8::MAX per `const_assert!` above; `addr_bytes` is max. 16 for IPv6.
    let rta_len = (size_of::<rtattr>() + addr_bytes(&remote).len()) as u16;
    attr.rta_len = rta_len;
    attr.rta_type = RTA_DST;

    let mut buf = vec![0u8; nlmsg_len as usize];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&hdr).cast(),
            buf.as_mut_ptr(),
            size_of::<nlmsghdr>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&rtm).cast(),
            buf.as_mut_ptr().add(size_of::<nlmsghdr>()),
            size_of::<rtmsg>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&attr).cast(),
            buf.as_mut_ptr()
                .add(size_of::<nlmsghdr>() + size_of::<rtmsg>()),
            size_of::<rtattr>(),
        );
        ptr::copy_nonoverlapping(
            addr_bytes(&remote).as_ptr(),
            buf.as_mut_ptr()
                .add(size_of::<nlmsghdr>() + size_of::<rtmsg>() + size_of::<rtattr>()),
            addr_bytes(&remote).len(),
        );
    };

    // Send RTM_GETROUTE message to get the interface index associated with the destination.
    if unsafe { write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) } < 0 {
        return Err(Error::last_os_error());
    }

    // Receive RTM_GETROUTE response.
    loop {
        let mut buf = vec![0u8; NETLINK_BUFFER_SIZE];
        let len = unsafe { recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if len < 0 {
            return Err(Error::last_os_error());
        }
        #[allow(clippy::cast_sign_loss)] // We handled negative sizes above, so this is OK.
        let len = len as usize;

        let mut offset = 0;
        while offset < len {
            let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(offset).cast::<nlmsghdr>()) };
            if hdr.nlmsg_seq == nlmsg_seq && hdr.nlmsg_type == RTM_NEWROUTE {
                // This is the response, parse through the attributes to find the interface index.
                let mut attr_ptr = unsafe {
                    buf.as_ptr()
                        .add(offset + size_of::<nlmsghdr>() + size_of::<rtmsg>())
                };
                let attr_end = unsafe { buf.as_ptr().add(offset + hdr.nlmsg_len as usize) };
                while attr_ptr < attr_end {
                    let attr = unsafe { ptr::read_unaligned(attr_ptr.cast::<rtattr>()) };
                    if attr.rta_type == RTA_OIF {
                        // We have our interface index.
                        let idx = unsafe {
                            ptr::read_unaligned(attr_ptr.add(size_of::<rtattr>()).cast())
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

fn if_name_mtu(if_index: i32, fd: BorrowedFd) -> Result<(String, usize), Error> {
    // Prepare RTM_GETLINK message to get the interface name and MTU for the interface with the
    // obtained index.
    #[allow(clippy::cast_possible_truncation)]
    // Structs lens are <= u8::MAX per `const_assert!`s above.
    let nlmsg_len = (size_of::<nlmsghdr>() + size_of::<ifinfomsg>()) as u32;
    let nlmsg_seq = 2;
    let hdr = prepare_nlmsg(RTM_GETLINK, nlmsg_len, nlmsg_seq);

    let mut ifim: ifinfomsg = unsafe { zeroed() };
    ifim.ifi_family = AF_UNSPEC_U8;
    ifim.ifi_type = ARPHRD_NONE;
    ifim.ifi_index = if_index;

    let mut buf = vec![0u8; nlmsg_len as usize];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&hdr).cast(),
            buf.as_mut_ptr(),
            size_of::<nlmsghdr>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&ifim).cast(),
            buf.as_mut_ptr().add(size_of::<nlmsghdr>()),
            size_of::<ifinfomsg>(),
        );
    }

    // Send RTM_GETLINK message.
    if unsafe { write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) } < 0 {
        return Err(Error::last_os_error());
    }

    // Receive RTM_GETLINK response.
    let mut ifname = None;
    let mut mtu = None;
    'recv: loop {
        let mut buf = vec![0u8; NETLINK_BUFFER_SIZE];
        let len = unsafe { recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if len < 0 {
            return Err(Error::last_os_error());
        }
        #[allow(clippy::cast_sign_loss)] // We handled negative sizes above, so this is OK.
        let len = len as usize;

        let mut offset = 0;
        while offset < len {
            let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(offset).cast::<nlmsghdr>()) };
            if hdr.nlmsg_seq == nlmsg_seq && hdr.nlmsg_type == RTM_NEWLINK {
                let mut attr_ptr = unsafe {
                    buf.as_ptr()
                        .add(offset + size_of::<nlmsghdr>() + size_of::<ifinfomsg>())
                };
                let attr_end = unsafe { buf.as_ptr().add(offset + hdr.nlmsg_len as usize) };
                while attr_ptr < attr_end {
                    let attr = unsafe { ptr::read_unaligned(attr_ptr.cast::<rtattr>()) };
                    if attr.rta_type == IFLA_IFNAME {
                        let name =
                            unsafe { CStr::from_ptr(attr_ptr.add(size_of::<rtattr>()).cast()) };
                        if let Ok(name) = name.to_str() {
                            // We have our interface name.
                            ifname = Some(name.to_string());
                        }
                    } else if attr.rta_type == IFLA_MTU {
                        mtu = Some(
                            unsafe {
                                ptr::read_unaligned(
                                    attr_ptr.add(size_of::<rtattr>()).cast::<c_uint>(),
                                )
                            }
                            .try_into()
                            .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?,
                        );
                    }
                    if ifname.is_some() && mtu.is_some() {
                        break 'recv;
                    }
                    let incr = aligned_by(attr.rta_len as usize, 4);
                    attr_ptr = unsafe { attr_ptr.add(incr) };
                }
            }
            offset += hdr.nlmsg_len as usize;
        }
    }

    let name = ifname.ok_or_else(default_err)?;
    let mtu = mtu.ok_or_else(default_err)?;
    Ok((name, mtu))
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Create a netlink socket.
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd == -1 {
        return Err(Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let if_index = if_index(remote, fd.as_fd())?;
    eprintln!("if_index: {}", if_index);
    if_name_mtu(if_index, fd.as_fd())
}
