package goping

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

type EthHeader struct {
	DestAddr MacAddr
	SrcAddr  MacAddr
	Type     uint16
}

func DecodeEth(b []byte) EthHeader {
	var eh EthHeader
	eh.DestAddr = *(*MacAddr)(unsafe.Pointer(&b[0]))
	eh.SrcAddr = *(*MacAddr)(unsafe.Pointer(&b[6]))
	eh.Type = *(*uint16)(unsafe.Pointer(&b[12]))
	return eh
}

func (eh EthHeader) Encode() [ETH_HEADER_SIZE]byte {
	b := [ETH_HEADER_SIZE]byte{}
	*(*MacAddr)(unsafe.Pointer(&b[0])) = eh.DestAddr
	*(*MacAddr)(unsafe.Pointer(&b[6])) = eh.SrcAddr
	*(*uint16)(unsafe.Pointer(&b[12])) = eh.Type
	return b
}

func (eh EthHeader) ToString() string {
	return fmt.Sprintf("DestAddr:%s,SrcAddr:%s,Type:0x%04x", eh.DestAddr.ToString(), eh.SrcAddr.ToString(), ntohs(eh.Type))
}

type ArpHeader struct {
	HardwareType  uint16
	ProtocolType  uint16
	HardwareLen   uint8
	ProtocolLen   uint8
	Operation     uint16
	SrcMacAddr    MacAddr
	TargetMacAddr MacAddr
	SrcIpAddr     IpAddr
	TargetIpAddr  IpAddr
}

func DecodeArp(b []byte) ArpHeader {
	var ah ArpHeader
	ah.HardwareType = *(*uint16)(unsafe.Pointer(&b[0]))
	ah.ProtocolType = *(*uint16)(unsafe.Pointer(&b[2]))
	ah.HardwareLen = *(*uint8)(unsafe.Pointer(&b[4]))
	ah.ProtocolLen = *(*uint8)(unsafe.Pointer(&b[5]))
	ah.Operation = *(*uint16)(unsafe.Pointer(&b[6]))
	ah.SrcMacAddr = *(*MacAddr)(unsafe.Pointer(&b[8]))
	ah.SrcIpAddr = *(*IpAddr)(unsafe.Pointer(&b[14]))
	ah.TargetMacAddr = *(*MacAddr)(unsafe.Pointer(&b[18]))
	ah.TargetIpAddr = *(*IpAddr)(unsafe.Pointer(&b[24]))
	return ah
}

func (ah ArpHeader) Encode() [ARP_HEADER_SIZE]byte {
	b := [ARP_HEADER_SIZE]byte{}
	*(*uint16)(unsafe.Pointer(&b[0])) = ah.HardwareType
	*(*uint16)(unsafe.Pointer(&b[2])) = ah.ProtocolType
	*(*uint8)(unsafe.Pointer(&b[4])) = ah.HardwareLen
	*(*uint8)(unsafe.Pointer(&b[5])) = ah.ProtocolLen
	*(*uint16)(unsafe.Pointer(&b[6])) = ah.Operation
	*(*MacAddr)(unsafe.Pointer(&b[8])) = ah.SrcMacAddr
	*(*IpAddr)(unsafe.Pointer(&b[14])) = ah.SrcIpAddr
	*(*MacAddr)(unsafe.Pointer(&b[18])) = ah.TargetMacAddr
	*(*IpAddr)(unsafe.Pointer(&b[24])) = ah.TargetIpAddr
	return b
}

func (ah ArpHeader) ToString() string {
	return fmt.Sprintf(
		"HardwareType:0x%04x,ProtocolType:0x%04x,HardwareLen:0x%02x,ProtocolLen:0x%02x,Operation:0x%04x,SrcMacAddr:%s,SrcIpAddr:%s,TargetMacAddr:%s,TargetIpAddr:%s",
		ntohs(ah.HardwareType), ntohs(ah.ProtocolType), ah.HardwareLen, ah.ProtocolLen, ntohs(ah.Operation), ah.SrcMacAddr.ToString(), ah.SrcIpAddr.ToString(), ah.TargetMacAddr.ToString(), ah.TargetIpAddr.ToString(),
	)
}

type IpHeader struct {
	VersionAndHeaderLen    uint8
	TypeOfService          uint8
	TotalLen               uint16
	Id                     uint16
	FlagsAndFragmentOffset uint16
	TTL                    uint8
	Protocol               uint8
	Checksum               uint16
	SrcAddr                IpAddr
	DestAddr               IpAddr
}

func DecodeIp(b []byte) IpHeader {
	var ih IpHeader
	ih.VersionAndHeaderLen = *(*uint8)(unsafe.Pointer(&b[0]))
	ih.TypeOfService = *(*uint8)(unsafe.Pointer(&b[1]))
	ih.TotalLen = *(*uint16)(unsafe.Pointer(&b[2]))
	ih.Id = *(*uint16)(unsafe.Pointer(&b[4]))
	ih.FlagsAndFragmentOffset = *(*uint16)(unsafe.Pointer(&b[6]))
	ih.TTL = *(*uint8)(unsafe.Pointer(&b[8]))
	ih.Protocol = *(*uint8)(unsafe.Pointer(&b[9]))
	ih.Checksum = *(*uint16)(unsafe.Pointer(&b[10]))
	ih.SrcAddr = *(*IpAddr)(unsafe.Pointer(&b[12]))
	ih.DestAddr = *(*IpAddr)(unsafe.Pointer(&b[16]))
	return ih
}

func (ih IpHeader) Encode() [IP_HEADER_SIZE]byte {
	b := [IP_HEADER_SIZE]byte{}
	*(*uint8)(unsafe.Pointer(&b[0])) = ih.VersionAndHeaderLen
	*(*uint8)(unsafe.Pointer(&b[1])) = ih.TypeOfService
	*(*uint16)(unsafe.Pointer(&b[2])) = ih.TotalLen
	*(*uint16)(unsafe.Pointer(&b[4])) = ih.Id
	*(*uint16)(unsafe.Pointer(&b[6])) = ih.FlagsAndFragmentOffset
	*(*uint8)(unsafe.Pointer(&b[8])) = ih.TTL
	*(*uint8)(unsafe.Pointer(&b[9])) = ih.Protocol
	*(*uint16)(unsafe.Pointer(&b[10])) = ih.Checksum
	*(*IpAddr)(unsafe.Pointer(&b[12])) = ih.SrcAddr
	*(*IpAddr)(unsafe.Pointer(&b[16])) = ih.DestAddr
	return b
}

func (ih IpHeader) ToString() string {
	return fmt.Sprintf(
		"Version:0x%02x,HeaderLen:%02x,TypeOfService:0x%02x,TotalLen:0x%04x,Id:0x%04x,FlagsAndFragmentOffset:0x%04x,TTL:0x%02x,Protocol:0x%02x,Checksum:0x%04x,SrcAddr:%s,DestAddr:%s",
		ih.Version(), ih.HeaderLen(), ih.TypeOfService, ntohs(ih.TotalLen), ntohs(ih.Id), ntohs(ih.FlagsAndFragmentOffset), ih.TTL, ih.Protocol, ntohs(ih.Checksum), ih.SrcAddr.ToString(), ih.DestAddr.ToString(),
	)
}

func (ih IpHeader) Version() uint8 {
	return ih.VersionAndHeaderLen >> 4
}

func (ih IpHeader) HeaderLen() uint8 {
	return ih.VersionAndHeaderLen & 0x0f
}

func (ih IpHeader) HeaderLenBytes() uint16 {
	return uint16(ih.HeaderLen()) * 4
}

func (ih IpHeader) DataSize() uint16 {
	return ntohs(ih.TotalLen) - ih.HeaderLenBytes()
}

func (ih *IpHeader) SetTotalLen(rxLen int, rxIp IpHeader) {
	ih.TotalLen = htons(ih.HeaderLenBytes() + uint16(rxLen) - ETH_HEADER_SIZE - rxIp.HeaderLenBytes())
}

func (ih *IpHeader) SetChecksum() {
	b := ih.Encode()
	ih.Checksum = htons(checksum(b[:], int(ih.HeaderLenBytes())))
}

type IcmpHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
}

func DecodeIcmp(b []byte) IcmpHeader {
	var ih IcmpHeader
	ih.Type = *(*uint8)(unsafe.Pointer(&b[0]))
	ih.Code = *(*uint8)(unsafe.Pointer(&b[1]))
	ih.Checksum = *(*uint16)(unsafe.Pointer(&b[2]))
	ih.Id = *(*uint16)(unsafe.Pointer(&b[4]))
	ih.Seq = *(*uint16)(unsafe.Pointer(&b[6]))
	return ih
}

func (ih IcmpHeader) Encode() [ICMP_HEADER_SIZE]byte {
	b := [ICMP_HEADER_SIZE]byte{}
	*(*uint8)(unsafe.Pointer(&b[0])) = ih.Type
	*(*uint8)(unsafe.Pointer(&b[1])) = ih.Code
	*(*uint16)(unsafe.Pointer(&b[2])) = ih.Checksum
	*(*uint16)(unsafe.Pointer(&b[4])) = ih.Id
	*(*uint16)(unsafe.Pointer(&b[6])) = ih.Seq
	return b
}

func (ih IcmpHeader) ToString() string {
	return fmt.Sprintf("Type:0x%02x,Code:0x%02x,Checksum:0x%04x,Id:0x%04x,Seq:0x%04x", ih.Type, ih.Code, ntohs(ih.Checksum), ntohs(ih.Id), ntohs(ih.Seq))
}

func (ih *IcmpHeader) SetChecksum(tx [PACKET_BUF_SIZE]byte, ip IpHeader) {
	ih.Checksum = htons(checksum(tx[ETH_HEADER_SIZE+ip.HeaderLenBytes():], int(ip.DataSize())))
}

func checksum(buf []uint8, length int) uint16 {
	var sum uint32

	for i := 0; i < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
