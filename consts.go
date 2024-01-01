package goping

const (
	ETH_HEADER_SIZE  = 14
	ARP_HEADER_SIZE  = 28
	IP_HEADER_SIZE   = 20
	ICMP_HEADER_SIZE = 8

	ICMP_TYPE_ECHO_REPLY uint8 = 0
	ICMP_TYPE_ECHO_REQ   uint8 = 8

	ARP_OP_REQUEST uint16 = 1
	ARP_OP_REPLY   uint16 = 2
)

var (
	MAC_BROADCAST = [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)
