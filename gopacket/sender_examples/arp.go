package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"go_test/examples/gopacket/common"


)

func main() {

	inactiveHandle, e := pcap.NewInactiveHandle("en0")
	if nil != e {
		log.Fatalln(e)
	}
	inactiveHandle.SetTimeout(30 * time.Second)
	inactiveHandle.SetPromisc(true)
	inactiveHandle.SetBufferSize(1 << 16)
	inactiveHandle.SetSnapLen(1 << 16)
	handle, e := inactiveHandle.Activate()
	if nil != e {
		log.Fatal(e)
	}
	defer handle.Close()

	ehternet := &layers.Ethernet{
		SrcMAC:       common.SMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   common.SMac,
		SourceProtAddress: common.SIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    common.DIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ehternet, arp)
	outgointBytes := buffer.Bytes()
	e = handle.WritePacketData(outgointBytes)
	if nil != e {
		log.Println("send fail,err:", e)
	} else {
		log.Println("success")
	}

}
