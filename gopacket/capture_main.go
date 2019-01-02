package main

import (
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

var iname = flag.String("i", "fgdg", "")
var topK = flag.Int("t", 10, "top number")
var captureTime = flag.Int("c", 10, "senconds to capture ")
var showDetail = flag.Bool("d", true, "show detail")
var writeFile = flag.Bool("w", true, "")

var (
	deviceWrappers []*DeviceWrapper
	stopChan       chan struct{}
	networkMap     map[uint64]gopacket.Flow
	any            bool
)

type ConnectionRecorder struct {
	flow  gopacket.Flow
	count uint64
}

type SendRecord struct {
	//sync.Mutex
	//sendDstMap sync.Map
	sendDstMap map[uint64]*Definition
}

type DownloadRecorder struct {
	peekDownBps, peekUpStreamBps         float64
	downStreamDataSize, upStreamDataSize uint64
}

type CountRecorder struct {
	errorReadPollTimes    uint64
	errorTimeOutPollTimes uint64
	packetErrorNumber     uint64
}

type Definition struct {
	ip     string
	mac    net.HardwareAddr
	counts uint64
}

type DeviceWrapper struct {
	name               string
	mac                net.HardwareAddr
	ip                 net.IP
	connectionRecorder map[uint64]*ConnectionRecorder
	sendRecord         *SendRecord
	downLoadRecorder   *DownloadRecorder
	countRecorder      *CountRecorder
	packetChan         chan gopacket.Packet
	writeFileError     error
}

func NewDeviceWrapper() *DeviceWrapper {
	return &DeviceWrapper{
		connectionRecorder: make(map[uint64]*ConnectionRecorder, 0),
		sendRecord: &SendRecord{
			sendDstMap: make(map[uint64]*Definition, 0),
		},
		downLoadRecorder: &DownloadRecorder{},
		countRecorder:    &CountRecorder{},
		packetChan:       make(chan gopacket.Packet, 1024),
	}
}

func main() {
	flag.Parse()
	go Receive(*iname)
	time.Sleep(time.Second * time.Duration(*captureTime))
	fmt.Println(" ended,show detail")
	stopChan <- struct{}{}
	Show()
	fmt.Println("exit")
}

func Show() {
	if any {
		for _, deviceWrapper := range deviceWrappers {
			deviceWrapper.show()
		}
	} else {
		wrapper, _ := GetDeviceByName(*iname)
		wrapper.show()
	}
}

func (d DeviceWrapper) show() {
	defer func() {
		if err := recover(); nil != err {
			fmt.Printf("[show] device:%s, occur error:%v", d.name, err)
		}
	}()
	d.countRecorder.show()
	d.downLoadRecorder.show()
	d.sendRecord.show(*topK)
	fmt.Printf("\n device:%s=============\n 通信数:%d \n ", d.name, len(d.connectionRecorder))
}

func (s *SendRecord) show(topK int) {
	fmt.Println("本地向如下ip地址发送消息,top:", topK)
	values := make([]*Definition, 0)
	for _, value := range s.sendDstMap {
		values = append(values, value)
	}

	length := len(values)
	if length < topK {
		topK = length
	}
	qSort(values, 0, length-1, topK)
	fmt.Println(fmt.Sprintf(strings.Repeat("=", 19) + "destinition" + strings.Repeat("=", 19) + "totalCounts"))
	for i := 0; i < topK; i++ {
		s := strings.Repeat(" ", 19) + "%v" + strings.Repeat(" ", 19) + "%d" + "\n"
		fmt.Printf(s, values[i].ip, values[i].counts)
	}
}

func (c *CountRecorder) show() {
	fmt.Printf("read error times:%d ====== timeout times: %d========packet error times:%d",
		c.errorReadPollTimes, c.errorTimeOutPollTimes, c.packetErrorNumber)
}

func (r *DownloadRecorder) calBps(name string) {
	for {
		select {
		case <-stopChan:
			fmt.Println("stop calucating bytes")
			return
		default:
			tempDownSize := float64(r.downStreamDataSize) / 1024 / 1
			tempUpSize := float64(r.upStreamDataSize) / 1024 / 1
			fmt.Printf("\r device:%s===== Down: %.2f KB/s \t Up: %.2f KB/s \n", name, tempDownSize, tempUpSize)
			if tempDownSize > r.peekDownBps {
				r.peekDownBps = tempDownSize
			}
			if tempUpSize > r.peekUpStreamBps {
				r.peekUpStreamBps = tempUpSize
			}
			r.upStreamDataSize = 0
			r.downStreamDataSize = 0
			time.Sleep(time.Second)
		}
	}
}

func (r *DownloadRecorder) show() {
	fmt.Printf(" \n \r 下载峰值: %.2f KB/s \t上传峰值: %.2f KB/s \n", r.peekDownBps, r.peekUpStreamBps)
}

func Receive(iname string) {
	foreachDevice := func() {
		for i := 0; i < len(deviceWrappers); i++ {
			go func(index int) {
				go deviceWrappers[index].receive()
			}(i)
		}
	}

	if iname == "" || iname == "any" {
		any = true
		foreachDevice()
	} else {
		deviceWrapper, e := GetDeviceByName(iname)
		if e != nil {
			any = true
			foreachDevice()
		} else {
			deviceWrapper.receive()
		}
	}
}
func (d *DeviceWrapper)receive() {
	inactiveHandle, e := pcap.NewInactiveHandle(d.name)
	if e != nil {
		log.Printf("[NewInactiveHandle]device:%s new error:", d.name)
		return
	}
	inactiveHandle.SetSnapLen(1 << 16)
	inactiveHandle.SetBufferSize(2048)
	inactiveHandle.SetTimeout(time.Second * 3)
	inactiveHandle.SetImmediateMode(false)
	inactiveHandle.SetPromisc(true)
	handle, e := inactiveHandle.Activate()
	if e != nil {
		log.Printf("[OpenLive] device:%s,error:%v", d.name, e)
		return
	}
	defer handle.Close()
	if *writeFile {
		go write2File(d)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	go d.downLoadRecorder.calBps(d.name)
	for {
		select {
		case <-stopChan:
			fmt.Println("receiver stop receiving packets")
			close(d.packetChan)
			return
		default:
			showPacketsStats(d, handle)
			packet, e := source.NextPacket()
			if e != nil {
				if e == pcap.NextErrorTimeoutExpired {
					d.countRecorder.errorTimeOutPollTimes++
					continue
				} else if e == io.EOF {
					fmt.Println("read end,exit")
					return
				} else if e == pcap.NextErrorReadError {
					d.countRecorder.errorReadPollTimes++
					fmt.Println("read error")
					continue
				} else {
					log.Printf("[NextPacket] device:%s,error:%v", d.name, e)
					return
				}
			}
			if errorLayer := packet.ErrorLayer(); nil != errorLayer {
				d.countRecorder.packetErrorNumber++
				continue
			}
			if *writeFile && d.writeFileError == nil {
				go func(p gopacket.Packet) {
					d.packetChan <- p
				}(packet)
			}
			handlePacket(packet, d)
		}
	}
}

func write2File(deviceWrapper *DeviceWrapper) {
	file, e := os.Create(strconv.Itoa(hashCode(deviceWrapper.name)) + "_test.pcap")
	if e != nil {
		log.Println("file path is not correct ")
		deviceWrapper.writeFileError = e
		return
	}
	defer file.Close()
	writer := pcapgo.NewWriter(file)
	e = writer.WriteFileHeader(1<<16, layers.LinkTypeEthernet)
	if e != nil {
		log.Println("[WriteFileHeader]error: ", e)
		return
	}
	for {
		select {
		case packet, ok := <-deviceWrapper.packetChan:
			if !ok {
				return
			}
			e = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if e != nil {
				log.Println("[WritePacket]error:", e)
			}
		}
	}
}

func showPacketsStats(deviceWrapper *DeviceWrapper, handle *pcap.Handle) {
	stat, err := handle.Stats()
	if nil != err {
		log.Fatal(err)
	}
	log.Printf("device:%s ======total received:%d,total dropped:%d,total ifdropped:%d",
		deviceWrapper.name, stat.PacketsReceived, stat.PacketsDropped, stat.PacketsIfDropped)
}

func handlePacket(packet gopacket.Packet, deviceWrapper *DeviceWrapper) {
	etherType := packet.Layer(layers.LayerTypeEthernet)
	if etherType != nil {
		ethernet := etherType.(*layers.Ethernet)
		if ethernet.SrcMAC.String() == deviceWrapper.mac.String() {
			deviceWrapper.downLoadRecorder.upStreamDataSize += uint64(len(packet.Data()))
		} else {
			deviceWrapper.downLoadRecorder.downStreamDataSize += uint64(len(packet.Data()))
		}
	}
	networkLayer := packet.NetworkLayer()
	if nil != networkLayer {
		flow := networkLayer.NetworkFlow()
		hashKey := flow.FastHash()
		if connectionRelation, ok := deviceWrapper.connectionRecorder[hashKey]; ok {
			connectionRelation.flow = flow
			connectionRelation.count++
		} else {
			connectionRelation = &ConnectionRecorder{}
			connectionRelation.flow = flow
			connectionRelation.count = 1
			deviceWrapper.connectionRecorder[hashKey] = connectionRelation
		}
		if flow.Src().String() == deviceWrapper.ip.String() {
			go deviceWrapper.sendRecord.record(flow.Dst())
		}
	}
	if *showDetail {
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
			fmt.Println("contents:", ip.Contents)
			fmt.Println("payload:", ip.Payload)
			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			fmt.Println("Protocol: ", ip.Protocol)
			fmt.Println()
		} else {
			fmt.Println("No IPv4 layer detected.")
		}
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

		// udp layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if nil != udpLayer {
			fmt.Println("UDP layer detected.")
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("from port:%d to port :%d ", udp.SrcPort, udp.DstPort)
			fmt.Println("payLoad:", udp.Payload)
			fmt.Println("contents: ", udp.Contents)
		} else {
			fmt.Println("No UDP layer detected")
		}
	}
}

func (s *SendRecord) record(dst gopacket.Endpoint) {
	key := dst.FastHash()
	if definition, ok := s.sendDstMap[key]; ok {
		definition.counts++
	} else {
		definition := &Definition{
			ip:     dst.String(),
			counts: 1,
		}
		s.sendDstMap[key] = definition
	}
}

func init() {
	stopChan = make(chan struct{})
	devices, err := pcap.FindAllDevs()

	if err != nil {
		panic(err)
	}
	interfaces, e := net.Interfaces()
	log.Printf("devices:%d,interfaces:%d", len(devices), len(interfaces))
	if e != nil {
		panic(e)
	}
	for _, device := range interfaces {
		if nil == device.HardwareAddr {
			continue
		}
		deviceWrapper := NewDeviceWrapper()
		deviceWrapper.mac = device.HardwareAddr
		if !containsInterface(&devices, device, deviceWrapper) {
			continue
		}
		addrs, e := device.Addrs()
		if e != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}

		for _, addr := range addrs {
			if ipNet := addr.(*net.IPNet); nil != ipNet {
				if ipv4 := ipNet.IP.To4(); nil != ipv4 {
					deviceWrapper.ip = ipv4
				}
			}
		}
		deviceWrappers = append(deviceWrappers, deviceWrapper)
	}
}

func containsInterface(devices *[]pcap.Interface, netDevice net.Interface, deviceWrapper *DeviceWrapper) bool {
	for _, device := range *devices {
		addresses := device.Addresses
		for _, address := range addresses {
			addrs, e := netDevice.Addrs()
			if e != nil {
				return false
			}
			for _, addr := range addrs {
				if ipnet := addr.(*net.IPNet); nil != ipnet && ipnet.IP.Equal(address.IP) {
					deviceWrapper.name = device.Name
					return true
				}
			}
		}
	}
	return false
}

func GetDeviceByName(iname string) (*DeviceWrapper, error) {
	for _, device := range deviceWrappers {
		if device.name == iname {
			return device, nil
		}
	}
	return nil, errors.New("none")
}

func qSort(definitions []*Definition, start, end, topK int) {
	if start >= end {
		return
	}
	p := paration(definitions, start, end)
	if p >= topK {
		qSort(definitions, start, p-1, topK)
	} else {
		qSort(definitions, start, p-1, topK)
		qSort(definitions, p+1, end, topK)
	}
}
func paration(values []*Definition, start, end int) int {
	keyDefinition := values[start]
	for start < end {
		for end > start && values[end].counts <= keyDefinition.counts {
			end--
		}
		values[start] = values[end]
		for start < end && values[start].counts >= keyDefinition.counts {
			start++
		}
		values[end] = values[start]
	}
	values[start] = keyDefinition
	return start
}

func hashCode(s string) int {
	v := int(crc32.ChecksumIEEE([]byte(s)))
	if v >= 0 {
		return v
	}
	if -v >= 0 {
		return -v
	}
	return 0
}
