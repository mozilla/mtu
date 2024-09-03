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

use log::trace;

/// Prepare a default error result.
fn default_result<T>() -> Result<(InterfaceId, T), Error> {
    Err(Error::new(
        ErrorKind::NotFound,
        "Local interface MTU not found",
    ))
}

type InterfaceId = u64;

/// Return a unique interface ID and the maximum transmission unit (MTU) of the local network
/// interface towards the destination [`SocketAddr`] given in `remote`.
///
/// The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some
/// platforms for some remote destinations. (For example, loopback destinations on
/// Windows.)
///
/// The returned interface ID is an opaque identifier that can be used to identify the local
/// interface. It is a hash of the interface name (on Linux and macOS) or interface index (on
/// Windows), and has the same stability guarantees as those identifiers.
///
/// # Examples
///
/// ```
/// let saddr = "127.0.0.1:443".parse().unwrap();
/// let (id, mtu) = mtu::get_interface_and_mtu(&saddr).unwrap();
/// println!("MTU towards {:?} is {}", saddr, mtu);
/// ```
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
pub fn get_interface_and_mtu(remote: &SocketAddr) -> Result<(InterfaceId, usize), Error> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[allow(unused_assignments)] // Yes, res is reassigned in the platform-specific code.
    let mut res = default_result();

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        // Make a new socket that is connected to the remote address. We use this to learn which
        // local address is chosen by routing.
        let socket = UdpSocket::bind((
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        ))?;
        socket.connect(remote)?;

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            res = get_interface_and_mtu_linux_macos(&socket);
        }

        #[cfg(target_os = "windows")]
        {
            res = get_interface_and_mtu_windows(&socket);
        }
    }

    trace!("MTU towards {:?} is {:?}", remote, res);
    res
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_interface_and_mtu_linux_macos(socket: &UdpSocket) -> Result<(InterfaceId, usize), Error> {
    #[cfg(target_os = "linux")]
    use std::{ffi::c_char, mem, os::fd::AsRawFd};
    use std::{
        ffi::{c_int, CStr},
        hash::{DefaultHasher, Hash, Hasher},
    };

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
        let mut hasher = DefaultHasher::new();
        iface.hash(&mut hasher);
        let id = hasher.finish();

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
                        if let Ok(mtu) = usize::try_from(data.ifi_mtu) {
                            res = Ok((id, mtu));
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
            ifr.ifr_name[..iface.len()].copy_from_slice(unsafe {
                &*(ptr::from_ref::<[u8]>(iface.as_bytes()) as *const [c_char])
            });
            if unsafe { ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &ifr) } != 0 {
                res = Err(Error::last_os_error());
            } else if let Ok(mtu) = usize::try_from(unsafe { ifr.ifr_ifru.ifru_mtu }) {
                res = Ok((id, mtu));
            }
        }
    }

    unsafe { freeifaddrs(ifap) };
    res
}

#[cfg(target_os = "windows")]
fn get_interface_mtu_windows(socket: &UdpSocket) -> Result<(InterfaceId, usize), Error> {
    use std::{ffi::c_void, hash::DefaultHasher, slice};

    use windows::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            FreeMibTable, GetIpInterfaceTable, GetUnicastIpAddressTable, MIB_IPINTERFACE_ROW,
            MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
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
                    if Ok(mtu) = iface.NlMtu.try_into() {
                        let mut hasher = DefaultHasher::new();
                        iface.InterfaceIndex.hash(&mut hasher);
                        let id = hasher.finish();
                        res = Ok((id, mtu));
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

/// Return the maximum transmission unit (MTU) of the local network interface towards the
/// destination [`SocketAddr`] given in `remote`.
///
/// The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some
/// platforms for some remote destinations. (For example, loopback destinations on
/// Windows.)
///
/// This function is a convenience wrapper around [`get_interface_and_mtu`] that only returns the
/// MTU. It is provided for compatibility with version 0.1 of the `mtu` crate.
///
/// # Examples
///
/// ```
/// let saddr = "127.0.0.1:443".parse().unwrap();
/// let mtu = mtu::get_interface_mtu(&saddr).unwrap();
/// println!("MTU towards {:?} is {}", saddr, mtu);
/// ```
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
pub fn get_interface_mtu(remote: &SocketAddr) -> Result<usize, Error> {
    get_interface_and_mtu(remote).map(|(_, mtu)| mtu)
}

#[cfg(test)]
mod test {
    use std::net::ToSocketAddrs;

    use log::warn;

    fn check_mtu(sockaddr: &str, ipv4: bool, expected: usize) {
        let addr = sockaddr
            .to_socket_addrs()
            .unwrap()
            .find(|a| a.is_ipv4() == ipv4);
        if let Some(addr) = addr {
            match super::get_interface_mtu(&addr) {
                Ok(mtu) => assert_eq!(mtu, expected),
                Err(e) => {
                    // Some GitHub runners don't have IPv6. Just warn if we can't get the MTU.
                    assert!(addr.is_ipv6());
                    warn!("Error getting MTU for {}: {}", sockaddr, e);
                }
            }
        } else {
            // Some GitHub runners don't have IPv6. Just warn if we can't get an IPv6 address.
            assert!(!ipv4);
            warn!("No IPv6 address found for {}", sockaddr);
        }
    }

    #[test]
    fn loopback_interface_mtu_v4() {
        #[cfg(target_os = "macos")]
        check_mtu("localhost:443", true, 16384);
        #[cfg(target_os = "linux")]
        check_mtu("localhost:443", false, 65_536);
        #[cfg(target_os = "windows")]
        check_mtu("localhost:443", false, 4_294_967_295);
    }

    #[test]
    fn loopback_interface_mtu_v6() {
        #[cfg(target_os = "macos")]
        check_mtu("localhost:443", false, 16384);
        #[cfg(target_os = "linux")]
        check_mtu("localhost:443", false, 65_536);
        #[cfg(target_os = "windows")]
        check_mtu("localhost:443", false, 4_294_967_295);
    }

    #[test]
    fn default_interface_mtu_v4() {
        check_mtu("ietf.org:443", true, 1500);
    }

    #[test]
    fn default_interface_mtu_v6() {
        check_mtu("ietf.org:443", false, 1500);
    }
}
