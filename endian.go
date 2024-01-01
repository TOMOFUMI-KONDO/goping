package goping

func ntohs(n uint16) uint16 {
	return (n&0xff)<<8 | (n >> 8)
}

func ntohl(n uint32) uint32 {
	return (n&0xff)<<24 | (n&0xff00)<<8 | (n&0xff0000)>>8 | (n >> 24)
}

func htons(n uint16) uint16 {
	return ntohs(n)
}

func htonl(n uint32) uint32 {
	return ntohl(n)
}
