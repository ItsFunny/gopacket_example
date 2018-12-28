package examples

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	dstIp          net.IP
	amount         int
	interval       int64
	interfaceSlice []map[string]interface{}
	devices        []pcap.Interface
)

func init() {

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
func SendFromAny() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("[FindAllDevs]error:", err)
		os.Exit(-1)
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
			log.Printf("send from ipv4:%v,localHardwareAddr:%v", srcIp, srcMac)
			for i := 0; i < amount; i++ {
				sendArp(handle, srcIp, dstIp, srcMac)
				time.Sleep(time.Second * time.Duration(interval))
			}
			handle.Close()
			wg.Done()
		}(i)
	}
	wg.Wait()
	os.Exit(-1)
}
func InitData(dip net.IP, at int, itl int64) {
	dstIp = dip
	amount = at
	interval = itl
}
func SendFromConcrete(iface string) {
	var sIp net.IP
	var sMac net.HardwareAddr
	handle, err := createHandle(iface)
	if err != nil {
		log.Println("the device is not exist")
		os.Exit(-1)
	}
	sIp = GetIpByName(iface)
	sMac = GetMacFromSlice(sIp)
	if sIp == nil || nil == sMac {
		log.Println("设备名称对应的ip地址不合法")
		handle.Close()
		return
	}
	for i := 0; i < amount; i++ {
		sendArp(handle, sIp, dstIp, sMac)
		time.Sleep(time.Second * time.Duration(interval))
	}
	handle.Close()
}

func createHandle(iface string) (*pcap.Handle, error) {
	return pcap.OpenLive(iface, 2048, false, 30*time.Second)
}
func sendArp(handle *pcap.Handle, srcIp, dstIp net.IP, srcMac net.HardwareAddr) {
	ether := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   srcMac,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	// 序列化,SerializeBuffer is specifically designed to handle packet writing
	// serializerBuffer提供了限定容量的函数:NewSerializeBufferExpectedSize
	// SerializeLayers 参数中的SerializeOptions 内部的元素是2个bool 变量,是否修正length以及是否检查checksum
	// SerializeBuffer内部的bytes属性就是要序列化之后的数据
	// serializebuffer 可以在slice中往前添加元素也可以往后添加元素,类似于双向链表
	// 提供了clear函数
	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()
	err := handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Println("发送arp数据包失败..")
	} else {
		log.Println("发送arp数据包成功")
	}
}
