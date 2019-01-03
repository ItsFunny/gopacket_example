package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var dstIpStr = flag.String("d", "120.78.240.211", "dstIp")
var iface = flag.String("i", "awdl0", "")
var sendTimes = flag.Int("s", 5, "amount of packets to be sent")
var interval = flag.Int64("t", 1, "send interval")
var (
	interfaceSlice []map[string]interface{}
	devices        []pcap.Interface
	packetTypes    [4]string
	dstIp          net.IP
	DMac           = net.HardwareAddr{0x52, 0x54, 0x00, 0x33, 0xc4, 0x54}
	SMac           = net.HardwareAddr{0xf0, 0x18, 0x98, 0x76, 0x8e, 0x57}
)


type Buffer struct {
	data  []byte
	start int
}

func main() {
	flag.Parse()
	dstIp = net.ParseIP(*dstIpStr)
	if dstIp == nil {
		log.Println("无效ip")
		flag.Usage()
		return
	}
	if *iface == "any" {
		SendFromAny()
	} else {
		ip, sMac := getLocalIpByName(*iface)
		if ip == nil || sMac == nil {
			log.Println("cant get local ip,check the interfaceName,send from local interfaces")
			SendFromAny()
		} else {
			SendFromConcrete(*iface)
		}
	}
	log.Println("exit")
}

func init() {
	packetTypes = [4]string{"arp", "tcp", "udp", "mdns",}
	if len(interfaceSlice) == 0 {
		interfaces, e := net.Interfaces()
		if e != nil {
			log.Fatal(e)
		}
		for _, itf := range interfaces {
			addrs, e := itf.Addrs()
			if e != nil {
				log.Fatal(e)
			}
			for _, addr := range addrs {
				tempMap := make(map[string]interface{})
				tempMap["ip"] = addr.(*net.IPNet).IP
				tempMap["mac"] = itf.HardwareAddr
				tempMap[addr.(*net.IPNet).IP.String()] = itf.HardwareAddr
				interfaceSlice = append(interfaceSlice, tempMap)
			}
		}
	}
	if len(devices) == 0 {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		devices = devs
	}
}

func SendFromAny() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("[FindAllDevs]error:", err)
		return
	}
	length := len(devices)
	wg := sync.WaitGroup{}
	wg.Add(length)

	for i := 0; i < length; i++ {
		go func(index int) {
			var srcMac net.HardwareAddr
			var srcIp net.IP
			addresses := devices[index].Addresses
			for _, addr := range addresses {
				if srcIp = addr.IP; srcIp.To4() != nil && !srcIp.IsLoopback() && !srcIp.Equal(net.ParseIP("0.0.0.0")) {
					srcMac = GetMacFromSlice(addr.IP)
				}
			}
			if srcMac == nil || srcIp == nil {
				wg.Done()
				return
			}
			handle, e := createHandle(devices[index].Name)
			if e != nil {
				log.Println(e)
				wg.Done()
				return
			}

			packetTypeLength := len(packetTypes)
			for i := 0; i < *sendTimes; i++ {
				typeName := packetTypes[rand.Intn(packetTypeLength)]
				bytes, e := PacketBuild(srcMac, DMac, srcIp, dstIp, typeName)
				if e != nil {
					log.Println("[PacketBuild]error:", e)
					continue
				}
				e = handle.WritePacketData(bytes)
				if e != nil {
					log.Println("[WritePacketData]error:", e)
					continue
				}
				log.Printf("send %s successfully which is from ipv4:%v,localHardwareAddr:%v  ", typeName, srcIp, srcMac)
				time.Sleep(time.Second * time.Duration(*interval))
			}
			handle.Close()
			wg.Done()
		}(i)
	}
	wg.Wait()
	os.Exit(-1)
}

func getLocalIpByName(iface string) (net.IP, net.HardwareAddr) {
	ifs, e := net.Interfaces()
	if nil != e {
		log.Fatalf("cant get local interfaces,error:%v", e)
	}
	for _, it := range ifs {
		if it.Name != iface {
			continue
		}
		addrs, _ := it.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if nil == ipnet.IP.To4() {
					continue
				}
				return ipnet.IP, it.HardwareAddr
			}
		}
	}
	return nil, nil
}

func SendFromConcrete(iface string) {
	var sIp net.IP
	var sMac net.HardwareAddr
	handle, err := createHandle(iface)
	if err != nil {
		log.Println("the device is not exist")
		return
	}
	sIp = GetIpByName(iface)
	sMac = GetMacFromSlice(sIp)
	if sIp == nil || nil == sMac {
		log.Println("设备名称对应的ip地址不合法")
		handle.Close()
		return
	}
	packetTypeLength := len(packetTypes)
	for i := 0; i < *sendTimes; i++ {
		typeName := packetTypes[rand.Intn(packetTypeLength)]
		bytes, e := PacketBuild(sMac, DMac, sIp, dstIp, typeName)
		if e != nil {
			log.Println("[PacketBuild]error:", e)
			continue
		}
		e = handle.WritePacketData(bytes)
		if e != nil {
			log.Println("[WritePacketData]error:", e)
			continue
		}
		fmt.Printf("send %s successfully \n", typeName)
		time.Sleep(time.Second * time.Duration(*interval))
	}
	handle.Close()
}

func GetMacFromSlice(ipNet net.IP) net.HardwareAddr {
	for _, ipMap := range interfaceSlice {
		if ipNet.Equal(ipMap["ip"].(net.IP)) {
			return ipMap["mac"].(net.HardwareAddr)
		}
	}
	return nil
}

func GetIpByName(name string) net.IP {
	for _, dev := range devices {
		if dev.Name == name {
			for _, addr := range dev.Addresses {
				if addr.IP.To4() != nil {
					return addr.IP
				}
			}
		}
	}
	return nil
}

func createHandle(iface string) (*pcap.Handle, error) {
	return pcap.OpenLive(iface, 2048, false, 30*time.Second)
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
	} else if policyType == "mdns" {
		data, err = buildMDNS(sMac, dMac, sIp, dIp)
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
		SrcMAC:       SMac,
		DstMAC:       DMac,
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


func (b *Buffer) PrependBytes(n int) []byte {
	length := cap(b.data) + n
	newData := make([]byte, length)
	copy(newData, b.data)
	b.start = cap(b.data)
	b.data = newData
	return b.data[b.start:]
}

func buildMDNS(sMAC, dMAC net.HardwareAddr, sIp, dIp net.IP) ([]byte, error) {
	ether := &layers.Ethernet{
		SrcMAC:       sMAC,
		DstMAC:       dMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		TTL:      uint8(255),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    sIp,
		DstIP:    dstIp,
	}
	bf := &Buffer{}
	mdns(bf, dIp.String())
	udpPayload := bf.data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(60666),
		DstPort: layers.UDPPort(5353),
	}
	err := udp.SetNetworkLayerForChecksum(ip4)
	if err != nil {
		return nil, err
	}

	udp.Payload = udpPayload
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // 自动计算长度
		ComputeChecksums: true, // 自动计算checksum
	}
	err = gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		return nil, err
	}
	outgoingPacket := buffer.Bytes()

	return outgoingPacket, nil
}

func mdns(buffer *Buffer, ip string) {
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(0))          // 0x0000 标识
	binary.BigEndian.PutUint16(b[2:], uint16(0x0100)) // 标识
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // 问题数
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // 资源数
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // 授权资源记录数
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // 额外资源记录数
	// 查询问题
	ipList := strings.Split(ip, ".")
	for j := len(ipList) - 1; j >= 0; j-- {
		ip := ipList[j]
		b = buffer.PrependBytes(len(ip) + 1)
		b[0] = uint8(len(ip))
		for i := 0; i < len(ip); i++ {
			b[i+1] = uint8(ip[i])
		}
	}
	b = buffer.PrependBytes(8)
	b[0] = 7 // 后续总字节
	copy(b[1:], []byte{'i', 'n', '-', 'a', 'd', 'd', 'r'})
	b = buffer.PrependBytes(5)
	b[0] = 4 // 后续总字节
	copy(b[1:], []byte{'a', 'r', 'p', 'a'})
	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type 和 classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(12))
	binary.BigEndian.PutUint16(b[2:], 1)
}
