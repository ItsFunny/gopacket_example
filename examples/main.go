package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go_test/gopacket/examples/common"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// 需要通过设备名称 查找对应的ip地址 以及mac地址,返回的应该是ipv4,ipv6 和error ,如果error不为空则continue
// mac:ip=1:n
var ipMacSlice []map[string]interface{}
var nameMacMap map[string]net.HardwareAddr
var deviceSlice []DeviceWrapper
var stopChan chan struct{}
var chatChan chan struct{}
var packetTypes [3]string

type Sender struct {
}

type Receiver struct {
}

type DeviceWrapper struct {
	name string
	mac  net.HardwareAddr
	ips  []net.IP
}

// 一个网卡往另外一个网卡发送消息
// 另外一个网卡接收消息
// 不限ipv4或者ipv6,不限包顶层协议
// 并且为了显示,2者通过chan同步
func main() {
	var (
		sendIndex, receiveIndex int
	)
	length := len(deviceSlice)
	if length < 2 {
		log.Println("not enough interfaces")
		// FIXME  备份计划
	}
	sendIndex = rand.Intn(length)
	for sendIndex == receiveIndex {
		receiveIndex = rand.Intn(length)
	}
	wg := sync.WaitGroup{}
	go send(deviceSlice[sendIndex], deviceSlice[receiveIndex], wg)



	// windows 下是不行的
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	stopChan <- struct{}{}
	stopChan <- struct{}{}
	close(stopChan)
	close(signalChan)
	log.Println("exit")
}

func send(senderDevice, receiverDevice DeviceWrapper, wg sync.WaitGroup) {
	handle, e := pcap.OpenLive(senderDevice.name, 1<<16, false, time.Second*8)
	if e != nil {
		log.Println("[send]OpenLive error:", e)
		wg.Done()
		return
	}
	defer handle.Close()
	packetTypeLength := len(packetTypes)
	sendIpsLength := len(senderDevice.ips)
	receiverIpsLength := len(receiverDevice.ips)
	// TODO 通过device 传递过来的得到其ip,ip需要经过过滤,不为空就行
	for {
		select {
		case <-stopChan:
			log.Println("[Sender] exit")
			return
		default:
			packetType:=packetTypes[rand.Intn(packetTypeLength)]
			datas, e := PacketBuild(senderDevice.mac, senderDevice.mac, senderDevice.ips[rand.Intn(sendIpsLength)],
				receiverDevice.ips[rand.Intn(receiverIpsLength)], packetType)
			if e != nil {
				log.Println("[send]#BuildPacket error:", e)
				continue
			}
			e = handle.WritePacketData(datas)
			if e != nil {
				log.Println("[send]#WritePacketData error:", e)
				continue
			} else {
				log.Printf("[Send] send %s data successfully",packetType)
				time.Sleep(time.Second * 2)
			}
		}
	}
}
func receive(deviceName string, wg sync.WaitGroup) {
	inactiveHandle, e := pcap.NewInactiveHandle(deviceName)
	if e != nil {
		log.Println("[receive]OpenLive error:", e)
		wg.Done()
		return
	}
	e = inactiveHandle.SetPromisc(true)
	e = inactiveHandle.SetImmediateMode(false)
	e = inactiveHandle.SetTimeout(time.Second * 8)
	e = inactiveHandle.SetBufferSize(2048)
	e = inactiveHandle.SetSnapLen(1 << 16)
	handle, e := inactiveHandle.Activate()
	if e != nil {
		wg.Done()
		return
	}
	defer handle.Close()

	gopacket.NewPacketSource(handle, handle.LinkType())
}

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

	//packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{})
	//if errorLayer := packet.ErrorLayer(); nil != errorLayer {
	//	return nil, errorLayer.Error()
	//}

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
	buffer:=gopacket.NewSerializeBuffer()
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
	buffer:=gopacket.NewSerializeBuffer()
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

func init() {
	stopChan = make(chan struct{}, 2)
	chatChan = make(chan struct{})
	nameMacMap = make(map[string]net.HardwareAddr)
	packetTypes = [3]string{"tcp", "arp", "udp"}
	interfaces, e := net.Interfaces()
	if e != nil {
		log.Fatal(e)
	}
	for _, device := range interfaces {
		if nil == device.HardwareAddr {
			continue
		}

		addrs, e := device.Addrs()
		if e != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		deviceWrapper := DeviceWrapper{name: device.Name,
			mac: device.HardwareAddr,
		}
		nameMacMap[device.Name] = device.HardwareAddr

		ips := make([]net.IP, 0)
		for _, addr := range addrs {
			if ipNet := addr.(*net.IPNet); nil != ipNet {
				ips = append(ips, ipNet.IP)
				m := make(map[string]interface{})
				m["ip"] = ipNet.IP
				m["mac"] = device.HardwareAddr
				ipMacSlice = append(ipMacSlice, m)
			}
		}
		deviceWrapper.ips = ips
		deviceSlice = append(deviceSlice, deviceWrapper)
	}

}

func GetMacByIp(ip net.IP) net.HardwareAddr {
	for _, m := range ipMacSlice {
		if ip.Equal(m["ip"].(net.IP)) {
			return m["mac"].(net.HardwareAddr)
		}
	}
	return nil
}

func GetMacByName(deviceName string) (net.HardwareAddr, bool) {
	addr, ok := nameMacMap[deviceName]
	return addr, ok
}
