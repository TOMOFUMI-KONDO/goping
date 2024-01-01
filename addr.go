package goping

import "fmt"

type MacAddr [6]uint8

func (ma MacAddr) ToString() string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x", ma[0], ma[1], ma[2], ma[3], ma[4], ma[5])
}

type IpAddr uint32

func (ia IpAddr) ToString() string {
	return fmt.Sprintf("%d.%d.%d.%d", ia&0xff, ia>>8&0xff, ia>>16&0xff, ia>>24)
}
