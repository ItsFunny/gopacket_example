package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go_test/examples/gopacket/common"
	"net"
)

func PacketBuild(sMac, dMac net.HardwareAddr, sIp, dIp net.IP, policyType string) ([]byte, error) {
	var data []byte
	var err error
	if policyType == "arp" {
		data, err = buildArp(sMac, sIp, dIp)
	} else if policyType == "tcp" {
		data, err = buildTcp(sIp, dIp, sMac, dMac)
	} else if policyType == "udp" {
		data, err = buildUdp(sIp, dIp, sMac, dMac)
	}
	if err != nil {
		return nil, err
	}

	return data, nil
}
func buildArp(sMac net.HardwareAddr, sIp, dIp net.IP) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	option := gopacket.SerializeOptions{}
	eth := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       common.SMac,
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		BaseLayer:         layers.BaseLayer{},
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeARP,
		HwAddressSize:     6,
		ProtAddressSize:   6,
		Operation:         1,
		SourceHwAddress:   sMac,
		SourceProtAddress: sIp,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    dIp,
	}
	serializeError := gopacket.SerializeLayers(buffer, option, eth, arp)
	if serializeError != nil {
		return nil, serializeError
	}
	return buffer.Bytes(), nil
}
func buildTcp(sIp, dIp net.IP, sMac, dMac net.HardwareAddr) ([]byte, error) {
	var etherType layers.EthernetType
	var option gopacket.SerializeOptions
	var ipLayer gopacket.SerializableLayer
	buffer := gopacket.NewSerializeBuffer()
	var err error
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(321),
		DataOffset: 5,
		Window:     1 << 10,
	}
	if ip := sIp.To4(); nil != ip {
		etherType = layers.EthernetTypeIPv4
		ipLayer = &layers.IPv4{
			BaseLayer: layers.BaseLayer{},
			IHL:       5,
			SrcIP:     ip,
			DstIP:     dIp,
		}
		err = tcp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		etherType = layers.EthernetTypeIPv6
		ipLayer = &layers.IPv6{
			SrcIP: sIp.To16(),
			DstIP: dIp,
		}
		err = tcp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv6))
	}
	if err != nil {
		return nil, err
	}
	eth := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: etherType,
	}

	err = gopacket.SerializeLayers(buffer, option, eth, ipLayer, tcp)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func buildUdp(sIp, dIp net.IP, sMac, dMac net.HardwareAddr) ([]byte, error) {
	var etherType layers.EthernetType
	var option gopacket.SerializeOptions
	var ipLayer gopacket.SerializableLayer
	var err error
	buffer := gopacket.NewSerializeBuffer()
	udp := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(135),
		DstPort:   layers.UDPPort(531),
	}
	if ip := sIp.To4(); nil != ip {
		etherType = layers.EthernetTypeIPv4
		ipLayer = &layers.IPv4{
			BaseLayer: layers.BaseLayer{},
			IHL:       5,
			SrcIP:     ip,
			DstIP:     dIp,
		}
		err = udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		etherType = layers.EthernetTypeIPv6
		ipLayer = &layers.IPv6{
			SrcIP: sIp.To16(),
			DstIP: dIp,
		}
		err = udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv6))
	}
	if err != nil {
		return nil, err
	}
	eth := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: etherType,
	}
	err = gopacket.SerializeLayers(buffer, option, eth, ipLayer, udp)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
