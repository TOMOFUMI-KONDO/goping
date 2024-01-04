package goping

import "testing"

func TestNtohs(t *testing.T) {
	n := uint16(0x1234)
	h := ntohs(n)

	expected := uint16(0x3412)
	if h != expected {
		t.Errorf("expected %x, but %x", expected, h)
	}
}

func TestNtohl(t *testing.T) {
	n := uint32(0x12345678)
	h := ntohl(n)

	expected := uint32(0x78563412)
	if h != expected {
		t.Errorf("expected %x, but %x", expected, h)
	}
}

func TestHtons(t *testing.T) {
	n := uint16(0x1234)
	h := htons(n)

	expected := uint16(0x3412)
	if h != expected {
		t.Errorf("expected %x, but %x", expected, h)
	}
}

func TestHtonl(t *testing.T) {
	n := uint32(0x12345678)
	h := htonl(n)

	expected := uint32(0x78563412)
	if h != expected {
		t.Errorf("expected %x, but %x", expected, h)
	}
}
