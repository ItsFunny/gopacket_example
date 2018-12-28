package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go_test/gopacket_examples"
	"log"
	"time"
)

func main() {

	handle, e := pcap.OpenLive("en0", 65535, false, time.Second*30)
	if nil!=e{
		log.Fatalln(e)
	}
	defer  handle.Close()

	ethernet:=&layers.Ethernet{
		SrcMAC:       gopacket_examples.SMac,
		DstMAC:       gopacket_examples.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4:=&layers.IPv4{
		BaseLayer: layers.BaseLayer{},
		Version:   4,
		IHL:       5,
		Length:    12333,
		Protocol:  layers.IPProtocolTCP,
		SrcIP:     gopacket_examples.SIp,
		DstIP:     gopacket_examples.DIp,
		TTL:       64,
	}
	tcp:=&layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(321),
		Window:     2 * 1 << 10,
	}
	opt:=gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	payload:=[]byte{1,2,3,3,2,1,1,1,1,1} // payload means applicaitonlayer data
	buffer := gopacket.NewSerializeBuffer()
	// 校验和,是必须的
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buffer,opt,ethernet,ipv4,tcp,gopacket.Payload(payload))
	bytes:=buffer.Bytes()
	e= handle.WritePacketData(bytes)
	if nil!=e{
		log.Println("err:",e)
	}else{
		log.Println("success")
	}
}