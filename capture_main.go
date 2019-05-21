package main

import (
	"flag"
	"fmt"
	"github.com/robfig/cron"
	"gopacket_example/jobs"
	"gopacket_example/web"
	"hash/crc32"
	"io"
	"log"
	"myLibrary/library/src/main/go/job"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

var iname = flag.String("i", "en0", "")
var topK = flag.Int("t", 10, "top number")
var captureTime = flag.Int("c", 10, "")
var showDetail = flag.Bool("d", false, "show detail")
var writeFile = flag.Bool("w", false, "")
var showStatss = flag.Bool("s", false, "")

var (
	deviceWrappers []*DeviceWrapper
	stopChan       chan struct{}
	networkMap     map[uint64]gopacket.Flow
	any            bool
)

var AutoClose = func() {
	time.Sleep(time.Second * time.Duration(*captureTime) * 1000)
	fmt.Println(" ended,show detail")
	Show()
	os.Exit(-1)
}

type ConnectionRecorder struct {
	flow  gopacket.Flow
	count uint64
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

type DuplicateAckWrapper struct {
	IsDuplicateACK bool
	IP             string
}

type DeviceWrapper struct {
	name               string
	mac                net.HardwareAddr
	ip                 net.IP
	connectionRecorder map[uint64]*ConnectionRecorder
	sendRecord         *web.SendRecord
	downLoadRecorder   *DownloadRecorder
	countRecorder      *CountRecorder
	packetChan         chan gopacket.Packet
	closed             bool
	writeFileError     error
}

// 判断是否是TCP Restramission的处理
type TcpRestramissionConsumer struct {
	sync.RWMutex
}

func main() {
	flag.Parse()
	go Receive(*iname)
	// go AutoClose()

	go func() {
		c := cron.New()
		spec := "0 0 1 1/1 * ?"
		c.AddFunc(spec, func() {
			log.Println("[begin quartz job]")
			web.PersistenceIPConnection()
			log.Println("[end quartz job]")
		})
		c.Start()
	}()

	go func() {
		ticker := time.NewTicker(time.Minute * 3)
		for {
			<-ticker.C
			log.Println("[begin monitor connection Map length]")
			web.MonitorConenctionMap()
			log.Println("[end monitor connection map length]")
		}
	}()

	go func() {
		http.HandleFunc("/download", web.GetLatestSpeed)
		http.HandleFunc("/connections", web.GetConnectionsTopNumber)
		http.ListenAndServe(":9000", nil)
		log.Println("启动web")
	}()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
	fmt.Println("exit gracefully")
	stopChan <- struct{}{}
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

func Receive(iname string) {
	foreachDevice := func() {
		if nil == deviceWrappers {
			fmt.Println("[foreachDevice]error the device map is empty ,exit ")
			os.Exit(-1)
		}
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

func (d *DeviceWrapper) receive() {
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
			if *showStatss {
				showPacketsStats(d, handle)
			}

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
				// FIXME OOM
				go func(p gopacket.Packet) {
					d.packetChan <- p
				}(packet)
			} else {
				if !d.closed {
					d.closed = true
					close(d.packetChan)
				}
			}
			handlePacket(packet, d)
		}
	}
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
			// go deviceWrapper.sendRecord.Record(flow.Dst())
			go web.Record(flow.Dst())
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

			// hashCode := hashCode(tcp.Contents)
			// wrapper := &jobs.TcpPacketWrapper{
			// 	Seq:               tcp.Ack,
			// 	DuplicateAckTimes: 0,
			// }
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
		validateJobExecutor := jobs.NewPacketValidateJobExecutor(jobs.NewValidateHandler())
		filterJobExecutor := jobs.NewFilterJobExecutor(validateJobExecutor)
		mediator := job.NewJobExecuteMediator(filterJobExecutor)

		res := mediator.Execute(job.NewAppEventWithCopy(jobs.FILTER_COPY).SetData(packet).SetJobType(jobs.JOB_FILTER, jobs.JOB_VALIDATE))
		fmt.Println(res)
	}
}

// FIXME
// func (t *TcpHolder) IsDuplicateAck(hashCode uint64, wrapper *TcpPacketWrapper) bool {
// 	var isDuplicateAck bool
// 	var isExist bool
// 	t.RLock()
// 	t.tcps.Each(func(index int, value interface{}) {
// 		if isDuplicateAck {
// 			return
// 		}
// 		if node := value.(*TcpNode); node.id == hashCode {
// 			isExist = true
// 			t.RUnlock()
// 			node.RLock()
// 			node.list.Each(func(index int, value interface{}) {
// 				if tcpWrapper := value.(*TcpPacketWrapper); tcpWrapper.Seq == wrapper.Seq {
// 					isDuplicateAck = true
// 					// 异常流量
// 					node.RUnlock()
// 					if tcpWrapper.DuplicateAckTimes < 2 {
// 						tcpWrapper.Lock()
// 						if tcpWrapper.DuplicateAckTimes < 2 {
// 							tcpWrapper.DuplicateAckTimes++
// 							tcpWrapper.Unlock()
// 						} else {
// 							tcpWrapper.Unlock()
// 							isDuplicateAck = true
// 							return
// 						}
// 					} else {
// 						return
// 					}
// 				}
// 			})
// 			if !isDuplicateAck {
// 				node.RUnlock()
// 				node.Lock()
// 				node.list.Add(wrapper)
// 				node.Unlock()
// 			}
// 		}
// 	})
// 	if !isExist {
// 		t.RUnlock()
// 		t.Lock()
// 		tcpNode := &TcpNode{
// 			id:   hashCode,
// 			list: arraylist.New(),
// 		}
// 		tcpNode.list.Add(wrapper)
// 		t.tcps.Add(tcpNode)
// 		t.Unlock()
// 	}
// 	return isDuplicateAck
// }

func write2File(deviceWrapper *DeviceWrapper) {
	bytes := []byte(deviceWrapper.name)
	file, e := os.Create(strconv.Itoa(hashCode(bytes)) + "_test.pcap")
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

func NewDeviceWrapper() *DeviceWrapper {
	return &DeviceWrapper{
		connectionRecorder: make(map[uint64]*ConnectionRecorder, 0),
		sendRecord: &web.SendRecord{
			SendDstMap: jobs.NewLRUCache(),
		},
		downLoadRecorder: &DownloadRecorder{},
		countRecorder:    &CountRecorder{},
		packetChan:       make(chan gopacket.Packet, 1024),
	}
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
	d.sendRecord.Show(*topK)
}
func GetDevices() []*DeviceWrapper {
	return deviceWrappers
}

func (c *CountRecorder) show() {
	fmt.Printf("read error times:%d ====== timeout times: %d========packet error times:%d",
		c.errorReadPollTimes, c.errorTimeOutPollTimes, c.packetErrorNumber)
}

func (r *DownloadRecorder) show() {
	fmt.Printf(" \n \r 下载峰值: %.2f KB/s \t上传峰值: %.2f KB/s \n",
		r.peekDownBps, r.peekUpStreamBps)
}

func (r *DownloadRecorder) calBps(name string) {
	for {
		select {
		case _, ok := <-stopChan:
			if ok {
				fmt.Println("stop calucating bytes")
				return
			}
		default:
			tempDownSize := float64(r.downStreamDataSize) / 1024 / 1
			tempUpSize := float64(r.upStreamDataSize) / 1024 / 1
			// fmt.Printf("\r device:%s===== Down: %.2f KB/s \t Up: %.2f KB/s \n", name, tempDownSize, tempUpSize)

			go func() {
				web.AddRecord(time.Now().Unix(), tempDownSize, tempUpSize)
			}()

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

// FIXME
func hashCode(bytes []byte) int {
	v := int(crc32.ChecksumIEEE(bytes))
	if v >= 0 {
		return v
	}
	if -v >= 0 {
		return -v
	}
	return 0
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
