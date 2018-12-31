package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go_test/gopacket/examples/common"
	"log"
	"net"
	"time"
)

// 测试从一台网卡发送到本地的另外一台网卡
// en3 send
// en4 receive

// en0,p2p0,awdl0,bridge0,utun0,en1,utun1,en2,en3,en4,lo0,git0,stf0,xhc0,xhc1,ap1,xhc20,vhc128
// lo0,gif0(e),stf0(e),xhc20(e),xhc0(e),xhc1(e),vhc128(e),en5(m,i),ap1(m),en0(m,ii),
// p2p0(m),awdl0(m,i),en1(m),en2(m),en3(m),en4(m),bridge0(m),utun0(i),utun1(i)
func main() {
	//send()
	//send2ConcreteMac()
	send2LocalOtherDevice()
}
func send() {
	handle, e := pcap.OpenLive("en2", 2048, false, time.Second*8)
	if nil != e {
		log.Fatalln(e)
	}
	defer handle.Close()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x3a, 0x00, 0x60, 0x8a, 0x54, 0x00},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		BaseLayer:         layers.BaseLayer{},
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeARP,
		HwAddressSize:     6,
		ProtAddressSize:   6,
		Operation:         1,
		SourceHwAddress:   net.HardwareAddr{0x3a, 0x00, 0x60, 0x8a, 0x54, 0x00},
		SourceProtAddress: net.ParseIP("1.2.3.4"),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    net.ParseIP("4.3.2.1"),
	}
	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	e = gopacket.SerializeLayers(buffer, opt, ethernet, arp)

	e = handle.WritePacketData(buffer.Bytes())
	if nil != e {
		log.Fatalln(e)
	} else {
		log.Println("send arp success")
	}
}

func send2ConcreteMac() {
	handle, e := pcap.OpenLive("en0", 2048, false, time.Second*8)
	if nil != e {
		log.Fatalln(e)
	}
	defer handle.Close()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x18, 0x98, 0x76, 0x8e, 0x57},
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		BaseLayer: layers.BaseLayer{},
		Version:   4,
		IHL:       5,
		TTL:       12,
		Protocol:  layers.IPProtocolTCP,
		SrcIP:     net.ParseIP("192.168.1.102"),
		DstIP:     common.DIp,
	}
	tcp := &layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(80),
		DataOffset: 5,
		Window:     1 << 15,
	}
	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	e = gopacket.SerializeLayers(buffer, opt, ethernet, ipv4, tcp)

	e = handle.WritePacketData(buffer.Bytes())
	if nil != e {
		log.Fatalln(e)
	} else {
		log.Println("send arp success")
	}
}

func send2LocalOtherDevice() {
	handle, e := pcap.OpenLive("en3", 2048, false, time.Second*8)
	if nil != e {
		log.Fatalln(e)
	}
	defer handle.Close()
	ethernet := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xf0, 0x18, 0x98, 0x76, 0x8e, 0x57},
		DstMAC: net.HardwareAddr{0x26, 0x7c, 0x3f, 0x4d, 0x5d, 0xc8},
		//DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	//ipv6 := &layers.IPv6{
	//	BaseLayer: layers.BaseLayer{},
	//	Version:   6,
	//	FlowLabel: 0,
	//	Length:    1 << 13,
	//	SrcIP:     net.ParseIP("192.168.1.102"),
	//	DstIP:     net.ParseIP("fe80::247c:3fff:fe4d:5dc8"),
	//}
	ipv4:=&layers.IPv4{
		Version:    4,
		IHL:        5,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("192.168.1.102"),
		DstIP:      net.ParseIP("127.0.0.1"),
	}
	udp := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(123),
		DstPort:   layers.UDPPort(321),
		Length:    1<<13,
	}
	udp.SetNetworkLayerForChecksum(ipv4)
	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	e = gopacket.SerializeLayers(buffer, opt, ethernet, ipv4, udp)
	if nil != e {
		log.Fatalln(e)
	}

	e = handle.WritePacketData(buffer.Bytes())
	if nil != e {
		log.Fatalln(e)
	} else {
		log.Println("send udp success")
	}
}
