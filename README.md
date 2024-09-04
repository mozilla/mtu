# MTU

A crate to return the name and maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`, optionally from a given local `SocketAddr`.

## Usage

This crate exports a single function `interface_and_mtu` that, given a pair of local and remote `SocketAddr`s, returns the name and [maximum transmission unit (MTU)](https://en.wikipedia.org/wiki/Maximum_transmission_unit) of the local network interface used by a socket bound to the local address and connected towards the remote destination.

If the local address is `None`, the function will let the operating system choose the local address based on the given remote address. If the remote address is `None`, the function will return the name and MTU of the local network interface with the given local address.

## Example

```rust
let saddr = "127.0.0.1:443".parse().unwrap();
let (name, mtu) = mtu::interface_and_mtu((None, saddr)).unwrap();
println!("MTU for {saddr:?} is {mtu} on {name}");
```

## Supported Platforms

* Linux
* macOS
* Windows

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

The returned interface name is obtained from the operating system.

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
