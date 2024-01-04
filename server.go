package goping

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const (
	TAP_DEV_NAME    = "tap00"
	PACKET_BUF_SIZE = 2048
)

var (
	IP_ADDR  = IpAddr(192) | IpAddr(168<<8) | IpAddr(200<<16) | IpAddr(10<<24)
	MAC_ADDR = MacAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

func Run() error {
	fd, err := createTapDev()
	if err != nil {
		return fmt.Errorf("failed to create TAP device: %w", err)
	}
	defer syscall.Close(fd)

	for {
		rx, rxLen, err := read(fd)
		if err != nil {
			return fmt.Errorf("failed to read: %w", err)
		}

		eth := DecodeEth(rx[:])

		switch ntohs(eth.Type) {
		case syscall.ETH_P_IP:
			if err := handleIp(fd, rx, rxLen, eth); err != nil {
				return fmt.Errorf("failed to handle ip: %w", err)
			}
		case syscall.ETH_P_ARP:
			if err := handleArp(fd, rx, eth); err != nil {
				return fmt.Errorf("failed to handle arp: %w", err)
			}
		}
	}
}

func createTapDev() (int, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("open error: /dev/net/tun")
	}

	ifr := createIfReq()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return 0, os.NewSyscallError("ioctl", errno)
	}

	return fd, nil
}

type ifReq struct {
	name  [16]byte
	flags uint16
	pad   [22]byte
}

func createIfReq() ifReq {
	ifr := ifReq{flags: syscall.IFF_TAP | syscall.IFF_NO_PI}
	copy(ifr.name[:], TAP_DEV_NAME)

	return ifr
}

func handleIp(fd int, rx [PACKET_BUF_SIZE]byte, rxLen int, eth EthHeader) error {
	if eth.DestAddr != MAC_ADDR {
		return nil
	}

	ip := DecodeIp(rx[ETH_HEADER_SIZE:])

	if ip.DestAddr != IP_ADDR {
		return nil
	}

	switch ip.Protocol {
	case syscall.IPPROTO_ICMP:
		if err := handleIcmp(fd, rx, rxLen, eth, ip); err != nil {
			return fmt.Errorf("failed to handle icmp: %w", err)
		}
	}

	return nil
}

func handleIcmp(fd int, rx [PACKET_BUF_SIZE]byte, rxLen int, eth EthHeader, ip IpHeader) error {
	icmp := DecodeIcmp(rx[ETH_HEADER_SIZE+ip.HeaderLenBytes():])

	switch icmp.Type {
	case ICMP_TYPE_ECHO_REQ:
		if err := replyIcmp(fd, rx, rxLen, eth, ip, icmp); err != nil {
			return fmt.Errorf("failed to reply icmp: %w", err)
		}
	}

	return nil
}

func replyIcmp(fd int, rx [PACKET_BUF_SIZE]byte, rxLen int, eth EthHeader, ip IpHeader, icmp IcmpHeader) error {
	reply, err := createIcmpEchoReply(rx, rxLen, eth, ip, icmp)
	if err != nil {
		return fmt.Errorf("failed to create icmp echo reply: %w", err)
	}

	if err := write(fd, reply); err != nil {
		return fmt.Errorf("failed to write icmp echo reply: %w", err)
	}

	log.Printf("Send icmp reply to %s", ip.SrcAddr.ToString())

	return nil
}

func createIcmpEchoReply(rx [PACKET_BUF_SIZE]byte, rxLen int, eth EthHeader, ip IpHeader, icmp IcmpHeader) ([]byte, error) {
	tx := [PACKET_BUF_SIZE]byte{}

	ethTx := EthHeader{
		SrcAddr:  eth.DestAddr,
		DestAddr: eth.SrcAddr,
		Type:     htons(syscall.ETH_P_IP),
	}
	*(*[ETH_HEADER_SIZE]byte)(unsafe.Pointer(&tx[0])) = ethTx.Encode()

	ipTx := IpHeader{
		VersionAndHeaderLen: 4<<4 | IP_HEADER_SIZE/4,
		TTL:                 64,
		Protocol:            syscall.IPPROTO_ICMP,
		SrcAddr:             ip.DestAddr,
		DestAddr:            ip.SrcAddr,
	}
	ipTx.SetTotalLen(rxLen, ip)
	ipTx.SetChecksum()
	*(*[IP_HEADER_SIZE]byte)(unsafe.Pointer(&tx[ETH_HEADER_SIZE])) = ipTx.Encode()

	leftSize := PACKET_BUF_SIZE - ETH_HEADER_SIZE + ip.HeaderLenBytes()
	if ip.DataSize() >= leftSize {
		return nil, errors.New("packet buffer size is too small")
	}

	icmpTx := IcmpHeader{
		Type: ICMP_TYPE_ECHO_REPLY,
		Code: icmp.Code,
		Id:   icmp.Id,
		Seq:  icmp.Seq,
	}
	*(*[ICMP_HEADER_SIZE]byte)(unsafe.Pointer(&tx[ETH_HEADER_SIZE+ipTx.HeaderLenBytes()])) = icmpTx.Encode()

	txOffset := ETH_HEADER_SIZE + ipTx.HeaderLenBytes() + ICMP_HEADER_SIZE
	rxOffset := ETH_HEADER_SIZE + ip.HeaderLenBytes() + ICMP_HEADER_SIZE
	if n := copy(tx[txOffset:], rx[rxOffset:rxLen]); n < 1 {
		return nil, fmt.Errorf("failed to copy icmp data (n: %d)", n)
	}

	icmpTx.SetChecksum(tx, ipTx)
	*(*[ICMP_HEADER_SIZE]byte)(unsafe.Pointer(&tx[ETH_HEADER_SIZE+ipTx.HeaderLenBytes()])) = icmpTx.Encode()

	return tx[:ETH_HEADER_SIZE+ntohs(ipTx.TotalLen)], nil
}

func handleArp(fd int, rx [PACKET_BUF_SIZE]byte, eth EthHeader) error {
	if eth.DestAddr != MAC_BROADCAST && eth.DestAddr != MAC_ADDR {
		return nil
	}

	arp := DecodeArp(rx[ETH_HEADER_SIZE:])

	switch ntohs(arp.Operation) {
	case ARP_OP_REQUEST:
		if err := handleArpReq(fd, eth, arp); err != nil {
			return fmt.Errorf("failed to handle arp request: %w", err)
		}
	}

	return nil
}

func handleArpReq(fd int, eth EthHeader, arp ArpHeader) error {
	if arp.TargetIpAddr != IP_ADDR {
		return nil
	}

	if err := replyArp(fd, eth, arp); err != nil {
		return fmt.Errorf("failed to reply arp: %w", err)
	}

	return nil
}

func replyArp(fd int, eth EthHeader, arp ArpHeader) error {
	reply := createArpReply(eth, arp)

	if err := write(fd, reply); err != nil {
		return fmt.Errorf("failed to write arp reply: %w", err)
	}

	log.Printf("Send arp reply to %s (asked who has %s)", arp.SrcIpAddr.ToString(), arp.TargetIpAddr.ToString())

	return nil
}

func createArpReply(eth EthHeader, arp ArpHeader) []byte {
	tx := [PACKET_BUF_SIZE]byte{}

	ethTx := EthHeader{
		SrcAddr:  MAC_ADDR,
		DestAddr: eth.SrcAddr,
		Type:     htons(syscall.ETH_P_ARP),
	}
	*(*[ETH_HEADER_SIZE]byte)(unsafe.Pointer(&tx[0])) = ethTx.Encode()

	arpTx := ArpHeader{
		HardwareType:  htons(syscall.ARPHRD_ETHER),
		ProtocolType:  htons(syscall.ETH_P_IP),
		HardwareLen:   6,
		ProtocolLen:   4,
		Operation:     htons(ARP_OP_REPLY),
		SrcMacAddr:    MAC_ADDR,
		SrcIpAddr:     IP_ADDR,
		TargetMacAddr: arp.SrcMacAddr,
		TargetIpAddr:  arp.SrcIpAddr,
	}
	*(*[ARP_HEADER_SIZE]byte)(unsafe.Pointer(&tx[ETH_HEADER_SIZE])) = arpTx.Encode()

	return tx[:ETH_HEADER_SIZE+ARP_HEADER_SIZE]
}
