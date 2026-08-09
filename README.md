# goping

A user-space ping (ICMP Echo) responder written in Go.

goping attaches to a Linux TAP device and speaks Ethernet, ARP, IPv4 and ICMP by itself, without
using the kernel network stack. It replies to ARP requests for its own address and answers ICMP
Echo Requests with Echo Replies, so that `ping` from the host succeeds against an IP address that
no kernel interface owns.

Based on the article [ユーザランドで動くping応答サーバを作る](https://eng-blog.iij.ad.jp/archives/21598).

## Requirements

- Linux with the TUN/TAP driver (`/dev/net/tun`)
- Go 1.21.5 or later
- `CAP_NET_ADMIN` (running as root is the simplest way)

The syscalls and constants used (`TUNSETIFF`, `IFF_TAP`, `ETH_P_IP`) are Linux-only, so the package
does not build on other platforms.

## Usage

Build the binary:

```sh
go build -o goping ./cmd
```

Start the server. It creates a TAP device named `tap00` and blocks, reading frames from it:

```sh
sudo ./goping
```

The TAP device is non-persistent and lives only while goping holds the file descriptor, so configure
it from another terminal after the server is running:

```sh
sudo ip link set tap00 up
sudo ip addr add 192.168.200.1/24 dev tap00
```

Now ping the address goping owns:

```sh
ping 192.168.200.10
```

goping logs every reply it sends:

```text
2024/01/01 00:00:00 Send arp reply to 192.168.200.1 (asked who has 192.168.200.10)
2024/01/01 00:00:00 Send icmp reply to 192.168.200.1
```

## Configuration

goping has no flags or environment variables. The settings are constants in the source:

| Setting        | Location    | Default                       |
| -------------- | ----------- | ----------------------------- |
| TAP device name| `server.go` | `tap00`                       |
| IPv4 address   | `server.go` | `192.168.200.10`              |
| MAC address    | `server.go` | `aa:bb:cc:dd:ee:ff`           |
| Packet buffer  | `server.go` | 2048 bytes                    |

`IP_ADDR` is stored in network byte order, so each octet is placed from the least significant byte
upward: `IpAddr(192) | IpAddr(168<<8) | IpAddr(200<<16) | IpAddr(10<<24)` means `192.168.200.10`.

## How it works

```text
ping ──> kernel ──> tap00 ──> goping (user space)
                                │
                   ┌────────────┴────────────┐
                   │ EthHeader               │
                   │  ├ ETH_P_ARP ─> ARP     │ reply to "who has 192.168.200.10"
                   │  └ ETH_P_IP  ─> IPv4    │
                   │        └ ICMP Echo Req  │ reply with Echo Reply
                   └─────────────────────────┘
```

1. `Run` opens `/dev/net/tun` and issues `TUNSETIFF` with `IFF_TAP | IFF_NO_PI` to create `tap00`.
2. Each read returns a raw Ethernet frame. The destination MAC is checked against `MAC_ADDR`
   (and the broadcast address for ARP), and the destination IP against `IP_ADDR`. Anything else is
   dropped.
3. ARP requests get a reply built from `MAC_ADDR` and `IP_ADDR`.
4. ICMP Echo Requests get a reply that swaps the source and destination addresses, copies the
   payload from the request, and recomputes the IPv4 and ICMP checksums.

Headers are converted between structs and byte arrays with `unsafe.Pointer` casts at fixed offsets.
Encoding and decoding are direct memory reinterpretations rather than field-by-field packing.

## Package layout

| File         | Contents                                                              |
| ------------ | --------------------------------------------------------------------- |
| `cmd/main.go`| Entry point                                                           |
| `server.go`  | TAP device setup, receive loop, ARP and ICMP reply construction       |
| `header.go`  | Ethernet, ARP, IPv4 and ICMP headers with encode, decode and checksum |
| `addr.go`    | `MacAddr` and `IpAddr` types                                          |
| `endian.go`  | `ntohs`, `ntohl`, `htons`, `htonl`                                    |
| `syscall.go` | Read and write wrappers over the TAP file descriptor                  |
| `consts.go`  | Header sizes and protocol constants                                   |

## Development

```sh
GOOS=linux go build ./...   # compiles from any host
go test ./...               # Linux only
```

The tests cover byte-order conversion and checksum calculation. They need a Linux host to run,
because the package they belong to fails to compile elsewhere.
