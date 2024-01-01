package goping

import (
	"errors"
	"fmt"
	"syscall"
)

func read(fd int) ([PACKET_BUF_SIZE]byte, int, error) {
	var rx [PACKET_BUF_SIZE]byte

	n, err := syscall.Read(fd, rx[:])
	if err != nil {
		return [PACKET_BUF_SIZE]byte{}, 0, fmt.Errorf("read error: %w", err)
	}
	if n == -1 {
		return [PACKET_BUF_SIZE]byte{}, 0, errors.New("read error: n is -1")
	}

	return rx, n, nil
}

func write(fd int, p []byte) error {
	n, err := syscall.Write(fd, p)
	if err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	if n == -1 {
		return errors.New("write error: n is -1")
	}

	return nil
}
