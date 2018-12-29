package _3_decoder

import (
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"

	"go_test/gopacket/examples/common"


)

// FIXME 示例

type DemoDecoder struct {
}

func (DemoDecoder) Decode(bytes []byte, builder gopacket.PacketBuilder) error {
	gopacket.NewPacket(bytes, DemoDecoder{}, gopacket.Lazy)
	return nil
}

//  DecodingLayerParser
// 通过NewDecodingLayerParser 方式创建,创建过程中内部通过map完成LinkType对decoder的映射
// 	第一个参数:对获取到的数据每次都先使用哪层的协议进行解析
//	第二个参数: 是一个可变长数组 ,代表的是一整套的协议流程,如一堆数据包都是这种结构:
//  ethernet->ipv6->udp 则对应的slice就是各自的layer,同时因为每层起始都是ethernet,所以第一个参数是LayerTypeEthernet
// 整个过程与剥洋葱一致
// 解析后的数据保存在哪? 保存在第二个参数中
// 如何根据不同的layer不同的处理:DecodeLayers中返回了包的具体结构,遍历即可然后对应的layertype选取对应的layer即可

// 核心函数: DecodeLayers 初次使用会将保存这个包的decode顺序的容器slice先清空[:0]
// 清空之后,先通过firstLayerType进行decode,之后会按slice的方向一个一个next下去,如果中途
// 返回error 既包的结构与预期的结构不符,就代表截断了(Truncated)则会返回,同时外部也可以人为做出反应
// 比packets或者nextpacket高效的地方在于不再需要重新allocate packet memory

func DecodeLayerParser() {
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var paylaod gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp,&paylaod)
	packet := getPacket()
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	err := parser.DecodeLayers(packet.Data(), &decodedLayers)
	for _, decodedLayer := range decodedLayers {
		if decodedLayer == layers.LayerTypeEthernet {
			log.Printf("from mac :%s to %s", eth.SrcMAC, eth.DstMAC)
		} else if decodedLayer == layers.LayerTypeIPv4 {
			log.Printf("from ipv4 :%s to %s  ", ipv4.SrcIP, ipv4.DstIP)
		} else if decodedLayer == layers.LayerTypeIPv6 {
			log.Printf("from ipv6 :%s to %s ", ipv6.SrcIP, ipv6.DstIP)
		} else if decodedLayer == layers.LayerTypeTCP {
			log.Printf("detected tcp.....")
		} else if decodedLayer == layers.LayerTypeUDP {
			log.Printf("detected udp.....")
		}
	}
	if nil != err {
		log.Println(err)
	}
	if parser.Truncated{
		log.Println("包结构顺序不正确,或者配置不正确")
	}
}

func getPacket() gopacket.Packet {
	buffer := gopacket.NewSerializeBuffer()
	option := gopacket.SerializeOptions{}
	ethernet := &layers.Ethernet{
		SrcMAC:       common.SMac,
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		BaseLayer: layers.BaseLayer{},
		Version:   4,
		IHL:       5,
		Length:    12333,
		Protocol:  layers.IPProtocolTCP,
		SrcIP:     common.SIp,
		DstIP:     common.DIp,
		TTL:       64,
	}
	tcp := &layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(321),
		Seq:        0,
		Ack:        0,
		DataOffset: 5,
		Window:     2 * 1 << 10,
	}
	gopacket.SerializeLayers(buffer, option, ethernet, ipv4, tcp)
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.DecodeOptions{})
	return packet
}
