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
    os::fd::AsRawFd,
    ptr, slice,
    str::Utf8Error,
};

use libc::{
    freeifaddrs, getifaddrs, getpid, if_data, if_indextoname, ifaddrs, in6_addr, in_addr,
    sockaddr_in, sockaddr_in6, sockaddr_storage, AF_INET, AF_INET6, AF_LINK, AF_UNSPEC, PF_ROUTE,
    RTAX_MAX, RTM_GET, RTM_VERSION,
};
use static_assertions::{const_assert, const_assert_eq};

use crate::{bsd::bindings::rt_msghdr, routesocket::RouteSocket};

#[allow(
    non_camel_case_types,
    clippy::struct_field_names,
    clippy::too_many_lines
)]
mod bindings {
    include!(env!("BINDINGS"));
}

#[cfg(any(apple, target_os = "freebsd", target_os = "openbsd"))]
const RTM_ADDRS: i32 = libc::RTA_DST;

#[cfg(target_os = "netbsd")]
const RTM_ADDRS: i32 = libc::RTA_DST | libc::RTA_IFP;

#[cfg(apple)]
const ALIGN: usize = size_of::<libc::c_int>();

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
// See https://github.com/freebsd/freebsd-src/blob/524a425d30fce3d5e47614db796046830b1f6a83/sys/net/route.h#L362-L371
// See https://github.com/NetBSD/src/blob/4b50954e98313db58d189dd87b4541929efccb09/sys/net/route.h#L329-L331
const ALIGN: usize = size_of::<libc::c_long>();

use crate::{aligned_by, default_err};

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_INET_U8: u8 = AF_INET as u8;
const_assert_eq!(AF_INET_U8 as i32, AF_INET);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_INET6_U8: u8 = AF_INET6 as u8;
const_assert_eq!(AF_INET6_U8 as i32, AF_INET6);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const AF_LINK_U8: u8 = AF_LINK as u8;
const_assert_eq!(AF_LINK_U8 as i32, AF_LINK);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const RTM_VERSION_U8: u8 = RTM_VERSION as u8;
const_assert_eq!(RTM_VERSION_U8 as i32, RTM_VERSION);

#[allow(clippy::cast_possible_truncation)] // Guarded by the following `const_assert_eq!`.
const RTM_GET_U8: u8 = RTM_GET as u8;
const_assert_eq!(RTM_GET_U8 as i32, RTM_GET);

const_assert!(size_of::<sockaddr_in>() + ALIGN <= u8::MAX as usize);
const_assert!(size_of::<sockaddr_in6>() + ALIGN <= u8::MAX as usize);
const_assert!(size_of::<rt_msghdr>() <= u8::MAX as usize);

struct IfAddrs(*mut ifaddrs);

impl Default for IfAddrs {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

impl IfAddrs {
    fn new() -> Result<Self, Error> {
        let mut ifap = Self::default();
        // getifaddrs allocates memory for the linked list of interfaces that is freed by
        // `IfAddrs::drop`.
        if unsafe { getifaddrs(ptr::from_mut(&mut ifap.0)) } != 0 {
            return Err(Error::last_os_error());
        }
        Ok(ifap)
    }

    const fn iter(&self) -> IfAddrPtr {
        IfAddrPtr(self.0)
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Free the memory allocated by `getifaddrs`.
            unsafe { freeifaddrs(self.0) };
        }
    }
}

struct IfAddrPtr(*mut ifaddrs);

impl IfAddrPtr {
    fn addr(&self) -> libc::sockaddr {
        unsafe { *(*self.0).ifa_addr }
    }

    fn name(&self) -> Result<&str, Utf8Error> {
        unsafe { CStr::from_ptr((*self.0).ifa_name).to_str() }
    }

    fn data(&self) -> Option<if_data> {
        let ifa_data = unsafe { (*self.0).ifa_data };
        if ifa_data.is_null() {
            None
        } else {
            Some(unsafe { *(ifa_data as *const if_data) })
        }
    }
}

impl Iterator for IfAddrPtr {
    type Item = Self;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_null() {
            return None;
        }
        let ifa = self.0;
        self.0 = unsafe { (*ifa).ifa_next };
        Some(Self(ifa))
    }
}

fn if_name_mtu(idx: u32) -> Result<(String, usize), Error> {
    let mut name = [0; libc::IF_NAMESIZE];
    // if_indextoname writes into the provided buffer.
    if unsafe { if_indextoname(idx, name.as_mut_ptr()).is_null() } {
        return Err(Error::last_os_error());
    }
    // Convert to Rust string.
    let name = unsafe {
        CStr::from_ptr(name.as_ptr())
            .to_str()
            .map_err(|err| Error::new(ErrorKind::Other, err))?
    };

    for ifa in IfAddrs::new()?.iter() {
        let ifa_name = ifa
            .name()
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        if ifa.addr().sa_family == AF_LINK_U8 && ifa_name == name {
            if let Some(ifa_data) = ifa.data() {
                if let Ok(mtu) = usize::try_from(ifa_data.ifi_mtu) {
                    return Ok((name.to_string(), mtu));
                }
            }
            return Err(default_err());
        }
    }
    Err(default_err())
}

#[repr(C)]
union SockaddrStorage {
    sin: sockaddr_in,
    sin6: sockaddr_in6,
}

impl SockaddrStorage {
    const fn len(&self) -> u8 {
        unsafe { self.sin.sin_len }
    }
}

impl From<IpAddr> for SockaddrStorage {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => SockaddrStorage {
                sin: sockaddr_in {
                #[allow(clippy::cast_possible_truncation)]
                // `sockaddr_in` len is <= u8::MAX per `const_assert!` above.
                sin_len: size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET_U8,
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_port: 0,
                sin_zero: [0; 8],
            },
            },
            IpAddr::V6(ip) => SockaddrStorage {
                sin6: sockaddr_in6 {
                #[allow(clippy::cast_possible_truncation)]
                // `sockaddr_in6` len is <= u8::MAX per `const_assert!` above.
                sin6_len: size_of::<sockaddr_in6>() as u8,
                sin6_family: AF_INET6_U8,
                sin6_addr: in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_scope_id: 0,
            },
            },
        }
    }
}

#[repr(C)]
struct RouteMessage {
    rtm: rt_msghdr,
    sa: SockaddrStorage,
}

impl RouteMessage {
    fn new(remote: IpAddr, seq: i32) -> Self {
        let sa = SockaddrStorage::from(remote);
        Self {
            rtm: rt_msghdr {
                #[allow(clippy::cast_possible_truncation)]
                // `rt_msghdr` len + `ALIGN` is <= u8::MAX per `const_assert!` above.
                rtm_msglen: (size_of::<rt_msghdr>() + aligned_by(sa.len().into(), ALIGN)) as u16,
                rtm_version: RTM_VERSION_U8,
                rtm_type: RTM_GET_U8,
                rtm_seq: seq,
                rtm_addrs: RTM_ADDRS,
                ..Default::default()
            },
            sa,
        }
    }

    const fn version(&self) -> u8 {
        self.rtm.rtm_version
    }

    const fn seq(&self) -> i32 {
        self.rtm.rtm_seq
    }

    const fn kind(&self) -> u8 {
        self.rtm.rtm_type
    }

    const fn len(&self) -> usize {
        self.rtm.rtm_msglen as usize
    }
}

impl From<&RouteMessage> for &[u8] {
    fn from(value: &RouteMessage) -> Self {
        debug_assert!(value.len() >= size_of::<Self>());
        unsafe { slice::from_raw_parts(ptr::from_ref(value).cast(), value.len()) }
    }
}

impl From<Vec<u8>> for rt_msghdr {
    fn from(value: Vec<u8>) -> Self {
        debug_assert!(value.len() >= size_of::<Self>());
        unsafe { ptr::read_unaligned(value.as_ptr().cast()) }
    }
}

fn if_index(remote: IpAddr) -> Result<u16, Error> {
    // Open route socket.
    let mut fd = RouteSocket::new(PF_ROUTE, AF_UNSPEC)?;

    // Send route message.
    let query = &RouteMessage::new(remote, fd.as_raw_fd());
    let query_version = query.version();
    let query_seq = query.seq();
    let query_type = query.kind();
    fd.write_all(query.into())?;

    // Read route messages.
    let pid = unsafe { getpid() };
    loop {
        let mut buf = vec![
            0u8;
            size_of::<rt_msghdr>() +
        // There will never be `RTAX_MAX` sockaddrs attached, but it's a safe upper bound.
         (RTAX_MAX as usize * size_of::<sockaddr_storage>())
        ];
        let len = fd.read(&mut buf[..])?;
        if len < size_of::<rt_msghdr>() {
            return Err(default_err());
        }
        let reply: rt_msghdr = buf.into();
        if reply.rtm_version == query_version && reply.rtm_pid == pid && reply.rtm_seq == query_seq
        {
            // This is a reply to our query.
            return if reply.rtm_type == query_type {
                // This is the reply we are looking for.
                Ok(reply.rtm_index)
            } else {
                Err(default_err())
            };
        }
    }
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    let if_index = if_index(remote)?;
    if_name_mtu(if_index.into())
}
