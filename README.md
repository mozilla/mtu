# MTU

A crate to return the name and maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`, optionally from a given local `SocketAddr`.

## Usage

This crate exports a single function `interface_and_mtu` that returns the name and [maximum transmission unit (MTU)](https://en.wikipedia.org/wiki/Maximum_transmission_unit) of the outgoing network interface towards a remote destination identified by an `IpAddr`,

## Example

```rust
let remote = "127.0.0.1".parse().unwrap();
let (name, mtu) = mtu::interface_and_mtu(remote).unwrap();
println!("MTU towards {remote:?} is {mtu} on {name}");
```

## Supported Platforms

* Linux
* macOS
* Windows

FreeBSD, NetBSD and OpenBSD support is waiting for [rust/libc#3714](https://github.com/rust-lang/libc/pull/3714).

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

The returned interface name is obtained from the operating system.

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
