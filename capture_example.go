package gopacket_examples

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/docker/go-units"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	deviceName =""
	snaplen int32=2048
	promisc=false
	timeout=time.Duration(time.Second*10)
)

func PrepareData(ifaceName string,sl int32,pc bool,timeLimited time.Duration){
	deviceName=ifaceName
	snaplen=sl
	promisc=pc
	timeout=timeLimited
}

func CaptureThroughHandle(){
	handle,err:=createHandleByConstructor()
	if err==nil{
		captureAndfilterByString(handle)
	}else{
		captureFromAny()
	}
}

func CaptureThroughPacketSource(){
	handle,err:=createHandleByConstructor()
	if err==nil{
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		showPacketsStats(handle)
		capturePacketByCallNextPacket(source)
	}else{
		log.Println("interface is not exist,detect local interfaces")
		captureFromAny()
	}
}

func captureFromAny(){
	devices, err := pcap.FindAllDevs()
	if err!=nil{
		log.Println("error FindAllDevs:",err)
		os.Exit(-1)
	}
	for i:=0;i<len(devices);i++{
		go func(index int) {
			handle, e := pcap.OpenLive(devices[index].Name, snaplen, promisc, timeout)
			if nil!=e{
				return
			}
			log.Println("start with the interface:",devices[index].Name)
			source := gopacket.NewPacketSource(handle, handle.LinkType())
			showPacketsStats(handle)
			capturePacketByCallNextPacket(source)
		}(i)
	}
}

// 1.1.1 通过构造函数传参创建
func createHandleByConstructor()(*pcap.Handle,error){
	return  pcap.OpenLive(deviceName, snaplen, promisc, timeout)
}
// 1.1.2 通过第三者初始化设置,可以起到定制的作用
func createHandleByDetail()*pcap.Handle{
	inactiveHandle, e := pcap.NewInactiveHandle(deviceName)
	if nil!=e{
		log.Fatal("[NewInactiveHandle]occur error:",e)
	}
	// 当为0时,则会一直等待直到有包到来
	// 在kernel 中延迟等待与tcp中的延迟确认类似,当到期时可以一次性处理多个包
	inactiveHandle.SetTimeout(timeout)
	inactiveHandle.SetImmediateMode(false) // 如果设置为true会覆盖timeout,收到packet会立即返回
	inactiveHandle.SetSnapLen( 1 << 16 )
	inactiveHandle.SetBufferSize( 1 * units.MiB)
	handle, e := inactiveHandle.Activate()
	if nil!=e{
		log.Println("[NewInactiveHandle]occur error:",e)
		os.Exit(-1)
	}
	return handle
}
// 1.2.1 简单通过配合handle#SetBPFFilter实现
func captureAndfilterByString(handle *pcap.Handle){
	handle.SetBPFFilter("tcp")
	for{
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err!=nil{
			if err ==pcap.NextErrorTimeoutExpired{
				continue
			}else if err==io.EOF{
				break
			}else{
				log.Println("err:",err)
				return
			}
		}
		showPacketsStats(handle)
		handlePacketBytes(data,ci)
	}
}
// 1.2.2 handle#NewBPF 通过返回的BPF#Match与CaptureInfo进行匹配过滤
func captureAndfilterByConcreteBPF(handle *pcap.Handle){
	bpf, e := handle.NewBPF("tcp")
	if e!=nil{
		log.Println("[filterByConcrete]occur error:",e)
		os.Exit(-1)
	}
	for{
		data, ci, err := handle.ReadPacketData()
		switch  {
		case err==io.EOF:
			log.Println("[captureAndfilterByConcreteBPF] end")
			return
		case err!=nil:
			log.Fatal(err)
		case bpf.Matches(ci,data):
			log.Println("syn/ack packet")
		default:
		}
		showPacketsStats(handle)
		handlePacketBytes(data,ci)
	}
}
// 1.2.3 通过BpfInstruction 方式,这个与afpacket中的RawInstruction类似
// 可以通过 bpf_util 将基于AFPACKET的RawInstruction转为Instruction
func captureAdndFilterByBPFInstruction(handle *pcap.Handle){
	// write the bpf code in bpf asm 详情: https://www.kernel.org/doc/Documentation/networking/filter.txt
	// let all IPv4/IPv6 packets with port 22 pass
	instructions := []pcap.BPFInstruction{
		{ 0x28,  0,  0, 0x0000000c },
		{ 0x15,  0,  8, 0x000086dd },
		{ 0x30,  0,  0, 0x00000014 },
		{ 0x15,  2,  0, 0x00000084 },
		{ 0x15,  1,  0, 0x00000006 },
		{ 0x15,  0, 17, 0x00000011 },
		{ 0x28,  0,  0, 0x00000036 },
		{ 0x15, 14,  0, 0x00000016 },
		{ 0x28,  0,  0, 0x00000038 },
		{ 0x15, 12, 13, 0x00000016 },
		{ 0x15,  0, 12, 0x00000800 },
		{ 0x30,  0,  0, 0x00000017 },
		{ 0x15,  2,  0, 0x00000084 },
		{ 0x15,  1,  0, 0x00000006 },
		{ 0x15,  0,  8, 0x00000011 },
		{ 0x28,  0,  0, 0x00000014 },
		{ 0x45,  6,  0, 0x00001fff },
		{ 0xb1,  0,  0, 0x0000000e },
		{ 0x48,  0,  0, 0x0000000e },
		{ 0x15,  2,  0, 0x00000016 },
		{ 0x48,  0,  0, 0x00000010 },
		{ 0x15,  0,  1, 0x00000016 },
		{ 0x06,  0,  0, 0x0000ffff },
		{ 0x06,  0,  0, 0x00000000 },
	}
	handle.SetBPFInstructionFilter(instructions)
}
func handlePacketBytes(data []byte,ci gopacket.CaptureInfo){
	options := gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   false,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	}
	linkType := layers.LinkTypeEthernet
	packet := gopacket.NewPacket(data, linkType, options)
	m := packet.Metadata()
	m.CaptureInfo = ci
	m.Truncated = m.Truncated || ci.CaptureLength < ci.Length
	handlePacket(packet)
}
// 1.4 通过handle#Stats获取packets相关信息,接收包的总数等信息
func showPacketsStats(handle *pcap.Handle){
	stat, err := handle.Stats()
	if nil!=err{
		log.Fatal(err)
	}
	log.Printf("total received:%d,total dropped:%d,total ifdropped:%d",
		stat.PacketsReceived,stat.PacketsDropped,stat.PacketsIfDropped)
}
// 2.2.1 通过packetSource#Packets获取packet 返回的是一个chan packet类型
func capturePacketByChan(source *gopacket.PacketSource){
	for {
		select {
		case p:=<-source.Packets():
			handlePacket(p)
		default:
		}
	}
}
// 2.2.2 通过packetSource#NextPacket 获取packet
func capturePacketByCallNextPacket(source *gopacket.PacketSource){
	for{
		packet, e := source.NextPacket()
		if e!=nil{
			if e == io.EOF {
				log.Println("read end ,exit")
				break
			} else if e == pcap.NextErrorTimeoutExpired {
				continue
			}else {
				log.Println("error:",e)
				os.Exit(-1)
			}
		}
		handlePacket(packet)
		time.Sleep(time.Second*5)
	}
}
// 通过LayerType获取指定layer(arp,tcp,udp,icmp等)
func handlePacket(packet gopacket.Packet){
	fmt.Println("====== handle packet========")
	fmt.Println("packet:",packet)
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