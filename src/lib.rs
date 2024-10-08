// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A crate to return the name and maximum transmission unit (MTU) of the local network interface
//! towards a given destination `SocketAddr`, optionally from a given local `SocketAddr`.
//!
//! # Usage
//!
//! This crate exports a single function `interface_and_mtu` that, given a pair of local and remote `SocketAddr`s, returns the name and [maximum transmission unit (MTU)](https://en.wikipedia.org/wiki/Maximum_transmission_unit) of the local network interface used by a socket bound to the local address and connected towards the remote destination.
//!
//! If the local address is `None`, the function will let the operating system choose the local
//! address based on the given remote address. If the remote address is `None`, the function will
//! return the name and MTU of the local network interface with the given local address.
//!
//! # Example
//!
//! ```rust
//! let saddr = "127.0.0.1:443".parse().unwrap();
//! let (name, mtu) = mtu::interface_and_mtu(&(None, saddr)).unwrap();
//! println!("MTU for {saddr:?} is {mtu} on {name}");
//! ```
//!
//! # Supported Platforms
//!
//! * Linux
//! * macOS
//! * Windows
//! * FreeBSD
//! * NetBSD
//! * OpenBSD
//!
//! # Notes
//!
//! The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for
//! some remote destinations. (For example, loopback destinations on Windows.)
//!
//! The returned interface name is obtained from the operating system.
//!
//! # Contributing
//!
//! We're happy to receive PRs that improve this crate. Please take a look at our [community
//! guidelines](CODE_OF_CONDUCT.md) beforehand.

use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

// Though the module includes `allow(clippy::all)`, that doesn't seem to affect some lints
#[allow(clippy::semicolon_if_nothing_returned, clippy::struct_field_names)]
#[cfg(windows)]
mod win_bindings;

/// Prepare a default error result.
fn default_result<T>() -> Result<(String, T), Error> {
    Err(Error::new(
        ErrorKind::NotFound,
        "Local interface MTU not found",
    ))
}

#[derive(Debug)]
pub enum SocketAddrs {
    Local(IpAddr),
    Remote(SocketAddr),
    Both((IpAddr, SocketAddr)),
}

impl From<&(IpAddr, SocketAddr)> for SocketAddrs {
    fn from((local, remote): &(IpAddr, SocketAddr)) -> Self {
        Self::Both((*local, *remote))
    }
}

impl From<&(Option<IpAddr>, SocketAddr)> for SocketAddrs {
    fn from((local, remote): &(Option<IpAddr>, SocketAddr)) -> Self {
        local.map_or(Self::Remote(*remote), |local| Self::Both((local, *remote)))
    }
}

impl From<&(IpAddr, Option<SocketAddr>)> for SocketAddrs {
    fn from((local, remote): &(IpAddr, Option<SocketAddr>)) -> Self {
        remote.map_or(Self::Local(*local), |remote| Self::Both((*local, remote)))
    }
}

/// Return the name and maximum transmission unit (MTU) of a local network interface.
///
/// Given a pair of local and remote [`SocketAddr`]s, return the name and maximum
/// transmission unit (MTU) of the local network interface used by a socket bound to the local
/// address and connected towards the remote destination.
///
/// If the local address is `None`, the function will let the operating system choose the local
/// address based on the given remote address. If the remote address is `None`, the function will
/// return the MTU of the local network interface with the given local address.
///
/// The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some
/// platforms for some remote destinations. (For example, loopback destinations on
/// Windows.)
///
/// The returned interface name is obtained from the operating system.
///
/// # Examples
///
/// ```
/// let saddr = "127.0.0.1:443".parse().unwrap();
/// let (name, mtu) = mtu::interface_and_mtu(&(None, saddr)).unwrap();
/// println!("MTU towards {saddr:?} is {mtu} on {name}");
/// ```
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
pub fn interface_and_mtu<A>(addrs: A) -> Result<(String, usize), Error>
where
    SocketAddrs: From<A>,
{
    let addrs = SocketAddrs::from(addrs);
    let local = match addrs {
        SocketAddrs::Local(local) | SocketAddrs::Both((local, _)) => local,
        SocketAddrs::Remote(remote) => {
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        }
    };
    // Let the OS choose an unused local port.
    let socket = UdpSocket::bind(SocketAddr::new(local, 0))?;
    match addrs {
        SocketAddrs::Local(_) => {}
        SocketAddrs::Remote(remote) | SocketAddrs::Both((_, remote)) => {
            socket.connect(remote)?;
        }
    }
    interface_and_mtu_impl(&socket)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "linux",
    target_os = "windows"
)))]
fn interface_and_mtu_impl(_socket: &UdpSocket) -> Result<(String, usize), Error> {
    default_result()
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "linux"
))]
fn interface_and_mtu_impl(socket: &UdpSocket) -> Result<(String, usize), Error> {
    use std::{
        ffi::{c_int, CStr},
        ptr,
    };
    #[cfg(target_os = "linux")]
    use std::{mem, os::fd::AsRawFd};

    use libc::{
        freeifaddrs, getifaddrs, ifaddrs, in_addr_t, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6,
    };
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    use libc::{if_data, AF_LINK};
    #[cfg(target_os = "linux")]
    use libc::{ifreq, ioctl};

    // Get the interface list.
    let mut ifap: *mut ifaddrs = ptr::null_mut();
    if unsafe { getifaddrs(&mut ifap) } != 0 {
        return Err(Error::last_os_error());
    }
    let ifap = ifap; // Do not modify this pointer.

    // First, find the name of the interface with the local IP address determined above.
    let mut cursor = ifap;
    let iface = loop {
        if cursor.is_null() {
            break None;
        }

        let ifa = unsafe { &*cursor };
        if !ifa.ifa_addr.is_null() {
            let saddr = unsafe { &*ifa.ifa_addr };
            if matches!(c_int::from(saddr.sa_family), AF_INET | AF_INET6)
                && match socket.local_addr()?.ip() {
                    IpAddr::V4(ip) => {
                        let saddr: sockaddr_in =
                            unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<sockaddr_in>()) };
                        saddr.sin_addr.s_addr == in_addr_t::to_be(ip.into())
                    }
                    IpAddr::V6(ip) => {
                        let saddr: sockaddr_in6 =
                            unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<sockaddr_in6>()) };
                        saddr.sin6_addr.s6_addr == ip.octets()
                    }
                }
            {
                break unsafe { CStr::from_ptr(ifa.ifa_name).to_str().ok() };
            }
        }
        cursor = ifa.ifa_next;
    };

    // If we have found the interface name we are looking for, find the MTU.
    let mut res = default_result();
    if let Some(iface) = iface {
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            // On macOS, we need to loop again to find the MTU of that interface. We need to
            // do two loops, because `getifaddrs` returns one entry per
            // interface and link type, and the IP addresses are in the
            // AF_INET/AF_INET6 entries for an interface, whereas the
            // MTU is (only) in the AF_LINK entry, whose `ifa_addr`
            // contains MAC address information, not IP address
            // information.
            let mut cursor = ifap;
            while !cursor.is_null() {
                let ifa = unsafe { &*cursor };
                if !ifa.ifa_addr.is_null() {
                    let saddr = unsafe { &*ifa.ifa_addr };
                    let name =
                        String::from_utf8_lossy(unsafe { CStr::from_ptr(ifa.ifa_name).to_bytes() });
                    if c_int::from(saddr.sa_family) == AF_LINK
                        && !ifa.ifa_data.is_null()
                        && name == iface
                    {
                        let data = unsafe { &*(ifa.ifa_data as *const if_data) };
                        if let Ok(mtu) = usize::try_from(data.ifi_mtu) {
                            res = Ok((iface.to_string(), mtu));
                        }
                        break;
                    }
                }
                cursor = ifa.ifa_next;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, we can get the MTU via an ioctl on the socket.
            let mut ifr: ifreq = unsafe { mem::zeroed() };
            ifr.ifr_name[..iface.len()]
                .copy_from_slice(unsafe { &*ptr::from_ref::<[u8]>(iface.as_bytes()) });
            if unsafe { ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &ifr) } != 0 {
                res = Err(Error::last_os_error());
            } else if let Ok(mtu) = usize::try_from(unsafe { ifr.ifr_ifru.ifru_mtu }) {
                res = Ok((iface.to_string(), mtu));
            }
        }
    }

    unsafe { freeifaddrs(ifap) };
    res
}

#[cfg(target_os = "windows")]
fn interface_and_mtu_impl(socket: &UdpSocket) -> Result<(String, usize), Error> {
    use std::{
        ffi::{c_void, CStr},
        ptr, slice,
    };

    use win_bindings::{
        if_indextoname, FreeMibTable, GetIpInterfaceTable, GetUnicastIpAddressTable, AF_INET,
        AF_INET6, AF_UNSPEC, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW,
        MIB_UNICASTIPADDRESS_TABLE, NO_ERROR,
    };

    let mut res = default_result();

    // Get a list of all unicast IP addresses with associated metadata.
    let mut addr_table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut addr_table) } != NO_ERROR {
        return Err(Error::last_os_error());
    }
    let addr_table = addr_table; // Do not modify this pointer.

    let addrs = unsafe {
        slice::from_raw_parts::<MIB_UNICASTIPADDRESS_ROW>(
            &(*addr_table).Table[0],
            (*addr_table).NumEntries as usize,
        )
    };

    // Get a list of all interfaces with associated metadata.
    let mut if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
    if unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut if_table) } != NO_ERROR {
        let error = Error::last_os_error();
        unsafe { FreeMibTable(addr_table as *const c_void) };
        return Err(error);
    }
    let if_table = if_table; // Do not modify this pointer.

    let ifaces = unsafe {
        slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
            &(*if_table).Table[0],
            (*if_table).NumEntries as usize,
        )
    };

    // Run through the list of addresses and find the one that matches the local IP
    // address.
    'addr_loop: for addr in addrs {
        let af = unsafe { addr.Address.si_family };
        let ip = socket.local_addr()?.ip();
        if (af == AF_INET && ip.is_ipv4() || af == AF_INET6 && ip.is_ipv6())
            && match ip {
                IpAddr::V4(ip) => {
                    u32::from(ip).to_be() == unsafe { addr.Address.Ipv4.sin_addr.S_un.S_addr }
                }
                IpAddr::V6(ip) => ip.octets() == unsafe { addr.Address.Ipv6.sin6_addr.u.Byte },
            }
        {
            // For the matching address, find local interface and its MTU.
            for iface in ifaces {
                if iface.InterfaceIndex == addr.InterfaceIndex {
                    if let Ok(mtu) = iface.NlMtu.try_into() {
                        let mut name = [0u8; 256]; // IF_NAMESIZE not available?
                        if unsafe { !if_indextoname(iface.InterfaceIndex, &mut name).is_null() } {
                            if let Ok(name) = CStr::from_bytes_until_nul(&name) {
                                if let Ok(name) = name.to_str() {
                                    res = Ok((name.to_string(), mtu));
                                }
                            }
                        } else {
                            res = Err(Error::last_os_error());
                        }
                    }
                    break 'addr_loop;
                }
            }
        }
    }

    unsafe { FreeMibTable(if_table as *const c_void) };
    unsafe { FreeMibTable(addr_table as *const c_void) };

    res
}

#[cfg(test)]
mod test {
    use std::{
        env,
        io::ErrorKind,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    };

    use rand::Rng;

    use crate::interface_and_mtu;

    #[derive(Debug)]
    struct NameMtu<'a>(Option<&'a str>, usize);

    impl PartialEq<NameMtu<'_>> for (String, usize) {
        fn eq(&self, other: &NameMtu<'_>) -> bool {
            other.0.map_or(true, |name| name == self.0) && other.1 == self.1
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd",))]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 16_384);
    #[cfg(target_os = "linux")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo"), 65_536);
    #[cfg(target_os = "windows")]
    const LOOPBACK: NameMtu = NameMtu(Some("loopback_0"), 4_294_967_295);
    #[cfg(target_os = "openbsd")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 32_768);
    #[cfg(target_os = "netbsd")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 33_624);

    // Non-loopback interface names are unpredictable, so we only check the MTU.
    const INET: NameMtu = NameMtu(None, 1_500);

    //  The tests can run in parallel, so try and find unused ports for all the tests.
    fn socket_with_addr(local_ip: IpAddr) -> SocketAddr {
        loop {
            let port = rand::thread_rng().gen_range(1024..65535);
            let saddr = SocketAddr::new(local_ip, port);
            let socket = UdpSocket::bind(saddr);
            match socket {
                // We found an unused port.
                Ok(socket) => return socket.local_addr().unwrap(),
                Err(e) => match e.kind() {
                    ErrorKind::AddrInUse | ErrorKind::PermissionDenied => {
                        // We hit a used or priviledged port, try again.
                        continue;
                    }
                    _ => {
                        // We hit another error. Pretend that worked by returning the socket
                        // address, so the actual code can hit the same error.
                        return saddr;
                    }
                },
            }
        }
    }

    fn local_v4() -> SocketAddr {
        socket_with_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    fn local_v6() -> SocketAddr {
        socket_with_addr(IpAddr::V6(Ipv6Addr::LOCALHOST))
    }

    fn inet_v4() -> SocketAddr {
        // cloudflare.com
        socket_with_addr(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)))
    }

    fn inet_v6() -> SocketAddr {
        // cloudflare.com
        socket_with_addr(IpAddr::V6(Ipv6Addr::new(
            0x26, 0x06, 0x47, 0x00, 0x68, 0x10, 0x84, 0xe5,
        )))
    }

    #[test]
    fn loopback_v4_loopback_v4() {
        assert_eq!(
            interface_and_mtu(&(local_v4().ip(), local_v4())).unwrap(),
            LOOPBACK
        );
    }

    #[test]
    fn loopback_v4_loopback_v6() {
        assert!(interface_and_mtu(&(local_v4().ip(), local_v6())).is_err());
    }

    #[test]
    fn loopback_v6_loopback_v4() {
        assert!(interface_and_mtu(&(local_v6().ip(), local_v4())).is_err());
    }

    #[test]
    fn loopback_v6_loopback_v6() {
        assert_eq!(
            interface_and_mtu(&(local_v6().ip(), local_v6())).unwrap(),
            LOOPBACK
        );
    }
    #[test]
    fn none_loopback_v4() {
        assert_eq!(interface_and_mtu(&(None, local_v4())).unwrap(), LOOPBACK);
    }

    #[test]
    fn none_loopback_v6() {
        assert_eq!(interface_and_mtu(&(None, local_v6())).unwrap(), LOOPBACK);
    }

    #[test]
    fn loopback_v4_none() {
        assert_eq!(
            interface_and_mtu(&(local_v4().ip(), None)).unwrap(),
            LOOPBACK
        );
    }

    #[test]
    fn loopback_v6_none() {
        assert_eq!(
            interface_and_mtu(&(local_v6().ip(), None)).unwrap(),
            LOOPBACK
        );
    }

    #[test]
    fn inet_v4_inet_v4() {
        assert!(interface_and_mtu(&(inet_v4().ip(), inet_v4())).is_err());
    }

    #[test]
    fn inet_v4_inet_v6() {
        assert!(interface_and_mtu(&(inet_v4().ip(), inet_v6())).is_err());
    }

    #[test]
    fn inet_v6_inet_v4() {
        assert!(interface_and_mtu(&(inet_v6().ip(), inet_v4())).is_err());
    }

    #[test]
    fn inet_v6_inet_v6() {
        assert!(interface_and_mtu(&(inet_v6().ip(), inet_v6())).is_err());
    }
    #[test]
    fn none_inet_v4() {
        assert_eq!(interface_and_mtu(&(None, inet_v4())).unwrap(), INET);
    }

    #[test]
    fn none_inet_v6() {
        if env::var("GITHUB_ACTIONS").is_ok() {
            // The GitHub CI environment does not have IPv6 connectivity.
            return;
        }
        assert_eq!(interface_and_mtu(&(None, inet_v6())).unwrap(), INET);
    }

    #[test]
    fn inet_v4_none() {
        assert!(interface_and_mtu(&(inet_v4().ip(), None)).is_err());
    }

    #[test]
    fn inet_v6_none() {
        assert!(interface_and_mtu(&(inet_v6().ip(), None)).is_err());
    }
}
