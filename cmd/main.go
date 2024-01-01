package main

import (
	"log"

	"github.com/tomofumi-kondo/goping"
)

func main() {
	if err := goping.Run(); err != nil {
		log.Fatal(err)
	}

	// net.ListenPacket()
	// syscall.Socket(0, syscall.SOCK_RAW, syscall.ETH_P)
}
