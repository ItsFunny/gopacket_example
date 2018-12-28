package examples

import (
	"net"
	"time"
)

const (
	RECEIVE_TIMEOUT = 100 * time.Millisecond
)
var (
	SMac=net.HardwareAddr{0xf0,0x18,0x98,0x76,0x8e,0x57}
	SIp=net.ParseIP("10.33.0.109")
	DIp=net.ParseIP("120.78.240.211")
	DMac=net.HardwareAddr{0x52,0x54,0x00,0x33,0xc4,0x54}
)