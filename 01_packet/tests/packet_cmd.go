package main

import (
	"fmt"
	"encoding/json"
	"log"

	"github.com/google/gopacket/layers"

	"go_test/examples/gopacket/01_packet"
	"go_test/examples/gopacket/common"
)

// 创建失败的packet
func createPacketWithFail(){
	bytes:=[]byte{1,2,3,4,5}
	// 设置skilError 为true,
	option := _1_packet.CreateDecodeOption(false, false, true, false)
	packet := _1_packet.CreatePacket(bytes,option)
	if errorLayer:=packet.ErrorLayer();nil!=errorLayer{
		log.Println("[createPacketWithFail] fail")
	}
	fmt.Println(packet.String())
}


func CreateNormPacket(){
	bytes:=common.SMac
	bytes=append(bytes,common.DMac...)
	marshal, _ := json.Marshal(layers.LayerTypeIPv4)
	bytes=append(bytes,marshal...)
	option:= _1_packet.CreateDecodeOption(false,false,false,false)
	packet := _1_packet.CreatePacket(bytes, option)
	if errorLayer:=packet.ErrorLayer();nil!=errorLayer{
		log.Println("[createNormPacket] wont be here")
	}
	log.Println(packet.String())
}

func main() {
	//createPacketWithFail()

	CreateNormPacket()
}