package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var deviceWrappers []DeviceWrapper
var sendRecorder *SendRecord
var recorder *DownloadRecorder
var countRecorder *CountRecorder
var stopChan chan struct{}
var packetChan chan gopacket.Packet
var networkMap map[uint64]gopacket.Flow
var connectionRecorder map[uint64]*ConnectionRecorder

var iname = flag.String("i", "en0", "")
var topK = flag.Int("t", 10, "top number")
var captureTime = flag.Int("c", 10, "senconds to capture ")
var showDetail = flag.Bool("d", true, "show detail")
var writeFile = flag.Bool("w", true, "")

type DeviceWrapper struct {
	name string
	mac  net.HardwareAddr
	ip   net.IP
}

type ConnectionRecorder struct {
	flow  gopacket.Flow
	count uint64
}

type SendRecord struct {
	sync.Mutex
	sendDstMap sync.Map
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

func main() {
	flag.Parse()
	go recorder.calBps()
	go receive(*iname)
	time.Sleep(time.Second * time.Duration(*captureTime))
	fmt.Println(" ended,show detail")
	stopChan <- struct{}{}
	show(*topK)
}

func show(topK int) {
	sendRecorder.show(topK)
	countRecorder.show()
	fmt.Printf("\n 通信数:%d \n ", len(connectionRecorder))
}

func (s *SendRecord) show(topK int) {
	fmt.Println("本地向如下ip地址发送消息,top:", topK)
	values := make([]*Definition, 0)

	s.sendDstMap.Range(func(key, value interface{}) bool {
		values = append(values, value.(*Definition))
		return true
	})
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

func (r *DownloadRecorder) calBps() {
	for {
		select {
		case <-stopChan:
			fmt.Println("stop calucating bytes")
			return
		default:
			tempDownSize := float64(r.downStreamDataSize) / 1024 / 1
			tempUpSize := float64(r.upStreamDataSize) / 1024 / 1
			fmt.Printf("\r Down: %.2f KB/s \t Up: %.2f KB/s \n", tempDownSize, tempUpSize)
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
	fmt.Printf(`\r 下载峰值: %.2f KB/s \t 
		上传峰值: %.2f KB/s \n, %v 至 %v 期间 平均下载速度为:"`, r.peekDownBps,
		r.peekUpStreamBps)
}

func receive(iname string) {
	var e error
	var deviceWrapper DeviceWrapper
	if iname == "" || iname == "any" {
		deviceWrapper = deviceWrappers[rand.Intn(len(deviceWrappers))]
	} else {
		deviceWrapper, e = GetDeviceByName(iname)
		if e != nil {
			panic(e)
		}
	}

	inactiveHandle, e := pcap.NewInactiveHandle(deviceWrapper.name)
	if e != nil {
		panic(e)
	}
	e = inactiveHandle.SetSnapLen(1 << 16)
	e = inactiveHandle.SetBufferSize(2048)
	e = inactiveHandle.SetTimeout(time.Second * 3)
	e = inactiveHandle.SetImmediateMode(false)
	e = inactiveHandle.SetPromisc(true)
	handle, e := inactiveHandle.Activate()
	if e != nil {
		panic(e)
	}
	defer handle.Close()
	if *writeFile {
		go write2File()
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-stopChan:
			fmt.Println("receiver stop receiving packets")
			close(packetChan)
			return
		default:
			showPacketsStats(handle)
			packet, e := source.NextPacket()
			if e != nil {
				// FIXME 这里的顺序应该是有问题的
				if e == pcap.NextErrorTimeoutExpired {
					countRecorder.errorTimeOutPollTimes++
					fmt.Println("timeout")
					continue
				} else if e == io.EOF {
					fmt.Println("read end,exit")
					return
				} else if e == pcap.NextErrorReadError {
					countRecorder.errorReadPollTimes++
					fmt.Println("read error")
					continue
				} else {
					panic(e)
				}
			}
			if errorLayer := packet.ErrorLayer(); nil != errorLayer {
				countRecorder.packetErrorNumber++
				continue
			}
			if *writeFile {
				go func(p gopacket.Packet) {
					packetChan <- p
				}(packet)
			}
			handlePacket(packet, &deviceWrapper)
		}
	}
}

func write2File() {
	file, e := os.Create("test.pcap")
	if e != nil {
		log.Println("file path is not correct ")
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
		case packet, ok := <-packetChan:
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

func showPacketsStats(handle *pcap.Handle) {
	stat, err := handle.Stats()
	if nil != err {
		log.Fatal(err)
	}
	log.Printf("total received:%d,total dropped:%d,total ifdropped:%d",
		stat.PacketsReceived, stat.PacketsDropped, stat.PacketsIfDropped)
}

// 显示对照着公司打算显示这些内容:
// top列表: 2个模块:入的方向和出的方向
//			每个模块都显示这些内容:源ip,目的ip,接收流量均值bps,发送流量均值bps,接收/发送包速率均值:pps
func handlePacket(packet gopacket.Packet, deviceWrapper *DeviceWrapper) {
	// 接下来就是写业务逻辑了
	etherType := packet.Layer(layers.LayerTypeEthernet)
	if etherType != nil {
		ethernet := etherType.(*layers.Ethernet)
		if ethernet.SrcMAC.String() == deviceWrapper.mac.String() {
			recorder.upStreamDataSize += uint64(len(packet.Data()))
		} else {
			recorder.downStreamDataSize += uint64(len(packet.Data()))
		}
	}
	networkLayer := packet.NetworkLayer()
	if nil != networkLayer {
		flow := networkLayer.NetworkFlow()
		hashKey := flow.FastHash()
		if connectionRelation, ok := connectionRecorder[hashKey]; ok {
			connectionRelation.flow = flow
			connectionRelation.count++
		} else {
			connectionRelation = &ConnectionRecorder{}
			connectionRelation.flow = flow
			connectionRelation.count = 1
			connectionRecorder[hashKey] = connectionRelation
		}
		if flow.Src().String() == deviceWrapper.ip.String() {
			go sendRecorder.record(flow.Dst())
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
	s.Lock()
	defer s.Unlock()
	key := dst.FastHash()
	if value, ok := s.sendDstMap.Load(key); ok {
		definition := value.(*Definition)
		definition.counts++
	} else {
		s.sendDstMap.Store(key, uint64(1))
		definition := &Definition{
			ip:     dst.String(),
			counts: 1,
		}
		s.sendDstMap.Store(key, definition)
	}
}

func init() {
	sendRecorder = &SendRecord{sendDstMap: sync.Map{},}
	countRecorder = &CountRecorder{}
	recorder = &DownloadRecorder{}
	connectionRecorder = make(map[uint64]*ConnectionRecorder)
	stopChan = make(chan struct{})
	packetChan = make(chan gopacket.Packet, 1024)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		panic(e)
	}
	for _, device := range interfaces {
		if nil == device.HardwareAddr {
			continue
		}
		if !containsInterface(&devices, device.Name) {
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

func containsInterface(devices *[]pcap.Interface, name string) bool {
	for _, device := range *devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

func GetDeviceByName(iname string) (DeviceWrapper, error) {
	for _, device := range deviceWrappers {
		if device.name == iname {
			return device, nil
		}
	}
	return DeviceWrapper{}, errors.New("none")
}

// FIXME 堆排序,或者归并
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
