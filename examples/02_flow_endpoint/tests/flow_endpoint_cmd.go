package main

import (
	"encoding/json"
	"log"

	"github.com/google/gopacket/layers"

	"go_test/gopacket/examples/01_packet"
	"go_test/gopacket/examples/common"
)

func main() {
	bytes:=common.SMac
	bytes=append(bytes,common.DMac...)
	marshal, _ := json.Marshal(layers.LayerTypeIPv4)
	bytes=append(bytes,marshal...)
	option:= _1_packet.CreateDecodeOption(false,false,false,false)
	packet := _1_packet.CreatePacket(bytes, option)
	flow := packet.LinkLayer().LinkFlow()
	src, dst := flow.Endpoints()
	log.Println("srcMac:",src.String())
	log.Println("dstMac:",dst.String())
}
