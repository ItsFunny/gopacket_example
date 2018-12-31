package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// TODO 修改计划了,不在本地进行互相发送了
// 而是send的时候直接全发送给远端服务器
// 但是receive处做文章,写好点
// 预计receive: 对所有流量进行监控
// 1. 省略握手的环节,记录有多少次用户交流,既通过flod-endpoint 的fasthash的对等性
//		预计的结构为:通过map存储,key为fasthash返回值,value则是自定的结构体,保存mac地址和ip地址 即可,既通过
//		这个可以统计连接数
//		在这基础上可以做附加功能:
// 2. 统计 tcp,udp,arp,icmp,mdns的次数

// 所以大体流程是这样
// 只不过前n秒的包,提供命令行提示是否捕获特定的包any表示所有,然后是否启动测试发送的程序
// 已经一个参数:是否末尾显示还是每次捕获到包都显示,
// 最后输出显示的内容有: 连接数(通过endpoint的fasthash来忽略握手,统计连接数)
// 记录哪些ip来访问过,以及统计次数
// 记录本机向哪些ip发过数据包,降序显示
// 统计tcp,udp,arp,icmp,mdns的次数
// 可以的话统计下异常数据包 --这个有点难感觉
// 综上:其实是有点复杂的逻辑,if判断挺多的会
// 额外:捕获包的时候通过packetsource吧,另外可以尝试通过packetsourceparser

// 发送包用的
var deviceWrappers []DeviceWrapper2
var sendRecorder *SendRecord     // 记录发包的时候与哪些ip地址通信
var recorder *Recorder           // 记录Bps,pps
var countRecorder *CountRecorder // 记录一些次数相关的信息
var stopChan2 chan struct{}

type DeviceWrapper2 struct {
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
type Recorder struct {
	downStreamDataSize uint64
	upStreamDataSize   uint64
}
type CountRecorder struct {
	errorReadPollTimes    uint64 // 从packetSource读取数据的时候出现错误
	errorTimeOutPollTimes uint64 // 从packetSource读取数据的时候超时
	// 从packetSource读取数据无error返回,但是当组装数据的时候发现数据包有问题,可以检测异常数据包吗?
	packetErrorNumber uint64
}

type Definition struct {
	ip     string
	mac    net.HardwareAddr
	counts uint64
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

var iname = flag.String("i", "en0", "")
var topK = flag.Int("t", 10, "top number")

func main() {
	// 命令行判断

	// 收包
	go recorder.calBps()
	go receive2(*iname)

	time.Sleep(time.Second * 10)
	fmt.Println("time ended,show detail")
	stopChan2 <- struct{}{}
	show(*topK)
}

// 开启子线程，每一秒计算一次该秒内的数据包大小平均值，并将下载、上传总量置零
func (r *Recorder) calBps() {
	for {
		select {
		case <-stopChan2:
			fmt.Println("stop calucating bytes")
			return
		default:
			os.Stdout.WriteString(fmt.Sprintf("\rDown:%.2fKb/s \t Up:%.2fKb/s \n",
				float32(r.downStreamDataSize)/1024/1, float32(r.upStreamDataSize)/1024/1))
			r.upStreamDataSize = 0
			r.downStreamDataSize = 0
			time.Sleep(time.Second)
		}
	}
}

func receive2(iname string) {
	var e error
	var deviceWrapper DeviceWrapper2
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
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-stopChan2:
			// 说明通道关闭
			fmt.Println("receiver stop receiving packets")
			return
		default:
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
			handlePacket2(packet, &deviceWrapper)
		}
	}
}

var networkMap map[uint64]gopacket.Flow
var connectionRecorder map[uint64]*ConnectionRecorder //保存着连接数,记录双方交流的次数,这样显示的时候可以显示最多的连接
// 显示对照着公司打算显示这些内容:
// top列表: 2个模块:入的方向和出的方向
//			每个模块都显示这些内容:源ip,目的ip,接收流量均值bps,发送流量均值bps,接收/发送包速率均值:pps
func handlePacket2(packet gopacket.Packet, deviceWrapper *DeviceWrapper2) {
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
		// 业务2,统计出方向的top10
		// 说明是本地发出去的
		if flow.Src().String() == deviceWrapper.ip.String() {
			go sendRecorder.record(flow.Dst())
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
	recorder = &Recorder{}
	connectionRecorder = make(map[uint64]*ConnectionRecorder)
	stopChan2 = make(chan struct{})
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
		deviceWrapper := DeviceWrapper2{name: device.Name,
			mac: device.HardwareAddr,
		}
		ips := make([]net.IP, 0)
		for _, addr := range addrs {
			if ipNet := addr.(*net.IPNet); nil != ipNet {
				if ipv4 := ipNet.IP.To4(); nil != ipv4 {
					deviceWrapper.ip = ipv4
				}
				ips = append(ips, ipNet.IP)
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

func GetDeviceByName(iname string) (DeviceWrapper2, error) {
	for _, device := range deviceWrappers {
		if device.name == iname {
			return device, nil
		}
	}
	return DeviceWrapper2{}, errors.New("none")
}

// 1. 先找到能用的设备,需要返回的是ip地址和设备mac地址,这里的ip统一用ipv4
func GetDevice() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	for _, device := range devices {
		addrs := device.Addresses
		for _, addr := range addrs {
			if ipv4 := addr.IP.To4(); nil != ipv4 && !ipv4.IsLoopback() {

			}
		}
	}
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
