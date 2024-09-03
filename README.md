# MTU

A crate to return the maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`.

## Usage

The main function exported by this crate is

```rust
pub fn interface_and_mtu(remote: &SocketAddr) -> Result<(String, usize), Error>
```

that returns the interface name and MTU of the local network interface used for transmission towards the `remote` destination, or an `Error` when the MTU could not be determined. It supports both IPv4 and IPv6.

## Supported Platforms

* Linux
* macOS
* Windows

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

The returned interface name is obtained from the operating system.

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
