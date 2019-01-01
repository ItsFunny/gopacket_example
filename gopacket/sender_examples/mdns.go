package main

import (
	"encoding/binary"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"go_test/examples/gopacket/common"
)

type Buffer struct {
	Data  []byte
	start int
}

func main() {
	handle, err := pcap.OpenLive("en0", 1024, false, 10*time.Second)
	if nil != err {
		log.Fatalf("pcap 打开失败:%v", err)
	}
	defer handle.Close()

	log.Println("[SendMDNS]ready to send mdns")

	ether := &layers.Ethernet{
		SrcMAC:       common.SMac,
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    common.SIp,
		DstIP:    common.DIp,
	}

	buffer := NewBuffer()
	BuildMDNSPacket(buffer, common.DIp.String())
	udpPayData := buffer.Data

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(60666),
		DstPort: layers.UDPPort(5353),
	}

	udp.SetNetworkLayerForChecksum(ipv4)
	udp.Payload = udpPayData
	serializeBuffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(serializeBuffer, opt, ether, ipv4, udp)
	if nil != err {
		log.Fatal("[SendMDNS]error:%V", err)
	}
	outgoingPacket := serializeBuffer.Bytes()

	err = handle.WritePacketData(outgoingPacket)
	if nil != err {
		log.Fatalf("发送udp数据包失败:%v", err)
	}
	log.Println("[SendMDNS]send mdns")
}

func NewBuffer() *Buffer {
	return &Buffer{
	}
}

func (b *Buffer) PrependBytes(n int) []byte {
	length := cap(b.Data) + n
	newData := make([]byte, length)
	copy(newData, b.Data)
	b.start = cap(b.Data)
	b.Data = newData
	return b.Data[b.start:]
}

// 根据ip生成含mdns请求包，包存储在 buffer里
func BuildMDNSPacket(buffer *Buffer, ip string) {
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
