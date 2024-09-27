# MTU

A crate to return the name and maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`, optionally from a given local `SocketAddr`.

## Usage

### `interface_and_mtu_of_socket`

This crate exports a function `interface_and_mtu_of_socket` that, given a `UdpSocket`, returns the name and [maximum transmission unit (MTU)](https://en.wikipedia.org/wiki/Maximum_transmission_unit) of the local network interface used by the socket.

#### Example for `interface_and_mtu_of_socket`

```rust
let socket = std::net::UdpSocket::bind("127.0.0.1:12345").unwrap();
let (name, mtu) = mtu::interface_and_mtu_of_socket(&socket).unwrap();
println!("MTU is {mtu} on {name}");
```

### `interface_and_mtu`

With the `addr` feature (which is enabled by default), this crate also exports a single function `interface_and_mtu` that, given a pair of local and remote `SocketAddr`s, returns the name and [maximum transmission unit (MTU)](https://en.wikipedia.org/wiki/Maximum_transmission_unit) of the local network interface used by a socket bound to the local address and connected towards the remote destination.

If the local address is `None`, the function will let the operating system choose the local address based on the given remote address. If the remote address is `None`, the function will return the name and MTU of the local network interface with the given local address.

#### Example for `interface_and_mtu`

```rust
let saddr = "127.0.0.1:443".parse().unwrap();
let (name, mtu) = mtu::interface_and_mtu(&(None, saddr)).unwrap();
println!("MTU for {saddr:?} is {mtu} on {name}");
```

## Supported Platforms

* Linux
* macOS
* Windows
* FreeBSD
* NetBSD
* OpenBSD

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

The returned interface name is obtained from the operating system.

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
