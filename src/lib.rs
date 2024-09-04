// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ptr,
};

// Though the module includes `allow(clippy::all)`, that doesn't seem to affect some lints
#[allow(clippy::semicolon_if_nothing_returned, clippy::struct_field_names)]
#[cfg(windows)]
mod win_bindings;

/// Prepare a default error result.
fn default_result<T>() -> Result<T, Error> {
    Err(Error::new(
        ErrorKind::NotFound,
        "Local interface MTU not found",
    ))
}

#[derive(Debug, Clone)]
pub enum SocketAddrs {
    Local(SocketAddr),
    Remote(SocketAddr),
    Both((SocketAddr, SocketAddr)),
}

impl From<(SocketAddr, SocketAddr)> for SocketAddrs {
    fn from((local, remote): (SocketAddr, SocketAddr)) -> Self {
        Self::Both((local, remote))
    }
}

impl From<(Option<SocketAddr>, SocketAddr)> for SocketAddrs {
    fn from((local, remote): (Option<SocketAddr>, SocketAddr)) -> Self {
        local.map_or(Self::Remote(remote), |local| Self::Both((local, remote)))
    }
}

impl From<(SocketAddr, Option<SocketAddr>)> for SocketAddrs {
    fn from((local, remote): (SocketAddr, Option<SocketAddr>)) -> Self {
        remote.map_or(Self::Local(local), |remote| Self::Both((local, remote)))
    }
}

impl From<SocketAddr> for SocketAddrs {
    fn from(local: SocketAddr) -> Self {
        Self::Local(local)
    }
}

/// Given a pair of local and remote [`SocketAddr`]s, return the maximum transmission unit (MTU)
/// of the local network interface used by a socket bound to the local address and connected
/// towards the remote destination.
///
/// If the local address is `None`, the function will let the operating system choose the local
/// address based on the given remote address. If the remote address is `None`, the function will
/// return the MTU of the local network interface with the given local address.
///
/// The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some
/// platforms for some remote destinations. (For example, loopback destinations on
/// Windows.)
///
/// # Examples
///
/// ```
/// let saddr = "127.0.0.1:443".parse().unwrap();
/// let mtu = mtu::interface_mtu((None, saddr)).unwrap();
/// println!("MTU for {saddr:?} is {mtu}");
/// ```
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
pub fn interface_mtu<A>(addrs: A) -> Result<usize, Error>
where
    SocketAddrs: From<A>,
    A: std::marker::Copy + std::fmt::Debug,
{
    let addrs = SocketAddrs::from(addrs);
    let local = match addrs {
        SocketAddrs::Local(local) | SocketAddrs::Both((local, _)) => local,
        SocketAddrs::Remote(remote) => SocketAddr::new(
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        ),
    };
    let socket = UdpSocket::bind(local)?;
    match addrs {
        SocketAddrs::Local(_) => {}
        SocketAddrs::Remote(remote) | SocketAddrs::Both((_, remote)) => {
            socket.connect(remote)?;
        }
    }
    interface_mtu_impl(&socket)
}

#[doc(hidden)]
#[deprecated(since = "0.1.2", note = "Use `interface_mtu()` instead")]
pub fn get_interface_mtu(remote: &SocketAddr) -> Result<usize, Error> {
    interface_mtu((None, *remote))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn interface_mtu_impl(socket: &UdpSocket) -> Result<usize, Error> {
    default_result()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn interface_mtu_impl(socket: &UdpSocket) -> Result<usize, Error> {
    use std::ffi::{c_int, CStr};
    #[cfg(target_os = "linux")]
    use std::{ffi::c_char, mem, os::fd::AsRawFd};

    use libc::{
        freeifaddrs, getifaddrs, ifaddrs, in_addr_t, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6,
    };
    #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
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
                        res = usize::try_from(data.ifi_mtu).or(res);
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
            ifr.ifr_name[..iface.len()].copy_from_slice(unsafe {
                &*(ptr::from_ref::<[u8]>(iface.as_bytes()) as *const [c_char])
            });
            if unsafe { ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &ifr) } != 0 {
                res = Err(Error::last_os_error());
            } else {
                res = unsafe { usize::try_from(ifr.ifr_ifru.ifru_mtu).or(res) };
            }
        }
    }

    unsafe { freeifaddrs(ifap) };
    res
}

#[cfg(target_os = "windows")]
fn interface_mtu_impl(socket: &UdpSocket) -> Result<usize, Error> {
    use std::{ffi::c_void, slice};

    use win_bindings::{
        FreeMibTable, GetIpInterfaceTable, GetUnicastIpAddressTable, AF_INET, AF_INET6, AF_UNSPEC,
        MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW,
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
                    res = iface.NlMtu.try_into().or(res);
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
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
        sync::atomic::AtomicU16,
    };

    use crate::interface_mtu;

    #[cfg(target_os = "macos")]
    const LOCAL_MTU: usize = 16_384;
    #[cfg(target_os = "linux")]
    const LOCAL_MTU: usize = 65_536;
    #[cfg(target_os = "windows")]
    const LOCAL_MTU: usize = 4_294_967_295;

    const INET_MTU: usize = 1500;

    //  The tests can run in parallel, so make sure to use different ports for all the tests.
    static PORT: AtomicU16 = AtomicU16::new(12345);

    fn new_port() -> u16 {
        PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn local_v4() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, new_port()))
    }

    fn local_v6() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, new_port(), 0, 0))
    }

    fn inet_v4() -> SocketAddr {
        format!("ietf.org:{}", new_port())
            .to_socket_addrs()
            .unwrap()
            .find(SocketAddr::is_ipv4)
            .unwrap()
    }

    fn inet_v6() -> SocketAddr {
        format!("ietf.org:{}", new_port())
            .to_socket_addrs()
            .unwrap()
            .find(SocketAddr::is_ipv4)
            .unwrap()
    }

    #[test]
    fn loopback_v4_loopback_v4() {
        assert_eq!(interface_mtu((local_v4(), local_v4())).unwrap(), LOCAL_MTU);
    }

    #[test]
    fn loopback_v4_loopback_v6() {
        assert!(interface_mtu((local_v4(), local_v6())).is_err());
    }

    #[test]
    fn loopback_v6_loopback_v4() {
        assert!(interface_mtu((local_v6(), local_v4())).is_err());
    }

    #[test]
    fn loopback_v6_loopback_v6() {
        assert_eq!(interface_mtu((local_v6(), local_v6())).unwrap(), LOCAL_MTU);
    }
    #[test]
    fn none_loopback_v4() {
        assert_eq!(interface_mtu((None, local_v4())).unwrap(), LOCAL_MTU);
    }

    #[test]
    fn none_loopback_v6() {
        assert_eq!(interface_mtu((None, local_v6())).unwrap(), LOCAL_MTU);
    }

    #[test]
    fn loopback_v4_none() {
        assert_eq!(interface_mtu((local_v4(), None)).unwrap(), LOCAL_MTU);
    }

    #[test]
    fn loopback_v6_none() {
        assert_eq!(interface_mtu((local_v6(), None)).unwrap(), LOCAL_MTU);
    }

    #[test]
    fn inet_v4_inet_v4() {
        assert!(interface_mtu((inet_v4(), inet_v4())).is_err());
    }

    #[test]
    fn inet_v4_inet_v6() {
        assert!(interface_mtu((inet_v4(), inet_v6())).is_err());
    }

    #[test]
    fn inet_v6_inet_v4() {
        assert!(interface_mtu((inet_v6(), inet_v4())).is_err());
    }

    #[test]
    fn inet_v6_inet_v6() {
        assert!(interface_mtu((inet_v6(), inet_v6())).is_err());
    }
    #[test]
    fn none_inet_v4() {
        assert_eq!(interface_mtu((None, inet_v4())).unwrap(), INET_MTU);
    }

    #[test]
    fn none_inet_v6() {
        assert_eq!(interface_mtu((None, inet_v6())).unwrap(), INET_MTU);
    }

    #[test]
    fn inet_v4_none() {
        assert!(interface_mtu((inet_v4(), None)).is_err());
    }

    #[test]
    fn inet_v6_none() {
        assert!(interface_mtu((inet_v6(), None)).is_err());
    }

    #[test]
    fn compat() {
        assert_eq!(interface_mtu(local_v4()).unwrap(), LOCAL_MTU);
    }
}
