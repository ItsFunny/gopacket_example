package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
)

func main() {
	if ring, err := pfring.NewRing("eth0", 65536, pfring.FlagPromisc); err != nil {
		panic(err)
	} else if err := ring.SetBPFFilter("tcp and port 80"); err != nil { // optional
		panic(err)
	} else if err := ring.Enable(); err != nil { // 必须进行校验
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}
func handlePacket(packet gopacket.Packet) {
	fmt.Println("====== handle packet========")
	fmt.Println("packet:", packet)
	for _, layer := range packet.Layers() {
		fmt.Println(layer.LayerType())
	}
	fmt.Println("============================")
	// ipv4 layer
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ip4Layer.(*layers.IPv4)
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	} else {
		fmt.Println("No IPv4 layer detected.")
	}
	// tcp layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Println("ACK: ", tcp.ACK)
		fmt.Println("SYN: ", tcp.SYN)
		fmt.Println("Seq: ", tcp.Seq)
		fmt.Println("DstPort: ", tcp.DstPort)
		fmt.Println("SrcPort: ", tcp.SrcPort)
		fmt.Println()
	} else {
		fmt.Println("No TCP layer detected.")
	}
}
