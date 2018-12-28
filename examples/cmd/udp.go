package main

import (
	"go_test/gopacket/examples"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

)

func main() {
	inactiveHandle, e := pcap.NewInactiveHandle("en0")
	if e!=nil{
		log.Fatal(e)
	}
	inactiveHandle.SetSnapLen(1<<16)
	inactiveHandle.SetBufferSize(1<<16)
	inactiveHandle.SetTimeout(examples.RECEIVE_TIMEOUT)
	inactiveHandle.SetPromisc(false)
	inactiveHandle.SetImmediateMode(false)
	handle, e := inactiveHandle.Activate()
	if e!=nil{
		log.Fatal(e)
	}
	defer  handle.Close()

	ethernet:=&layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       examples.SMac,
		DstMAC:       examples.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4:=&layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    examples.SIp,
		DstIP:    examples.DIp,
	}

	udp:=&layers.UDP{
		SrcPort:   layers.UDPPort(123),
		DstPort:   layers.UDPPort(321),
	}

	udp.SetNetworkLayerForChecksum(ipv4)

	opt:=gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	buffer:=gopacket.NewSerializeBuffer()

	serializeError := gopacket.SerializeLayers(buffer, opt, ethernet, ipv4, udp)
	if serializeError!=nil{
		log.Fatal(serializeError)
	}
	sendError := handle.WritePacketData(buffer.Bytes())
	if sendError!=nil{
		log.Fatal(sendError)
	}else{
		log.Println("[SendUdp]successfully")
	}


}
