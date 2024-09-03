# MTU

A crate to return the maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`.

## Usage

The main function exported by this crate is

```rust
pub fn interface_and_mtu(remote: &SocketAddr) -> Result<(String, usize), Error>
```

that returns an opaque identifier of the local network interface towards the `remote` destination together with its MTU, or an `Error` when the MTU could not be determined. It supports both IPv4 and IPv6.

## Supported Platforms

* Linux
* macOS
* Windows

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

The returned interface ID is an opaque identifier that can be used to identify the local interface. It is a hash of the interface name (on Linux and macOS) or interface index (on Windows), and has the same stability guarantees as those identifiers.

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
