package _4_serialize

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"go_test/gopacket/examples/common"

)

// 序列化还有一个重要的结构体:SerializBuffer
// SerializeBuffer is specifically designed to handle packet writing
// serializerBuffer提供了限定容量的函数:NewSerializeBufferExpectedSize
// SerializeLayers 参数中的SerializeOptions 内部的元素是2个bool 变量,是否修正length以及是否检查checksum
// SerializeBuffer内部的bytes属性就是要序列化之后的数据
// serializebuffer 可以在slice中往前添加元素也可以往后添加元素,类似于双向链表
// 提供了clear函数

// 解码对应的就会有序列化,序列化返回的都是[]byte,可以用于组装packet
// gopacket的layer都实现了SerizlieLayer接口

// 作用: 可以分层组装数据,最后统一 ,buffer 内部的数据与各层调用的顺序相反(类似于栈),但是这种情况下生成的数据是无法再次组装
// 成packet的,所以层得先从应用层->传输层->网络层->链路层这样的顺序
// SerializeLayers只是一个helper,是从尾巴开始SerializeTo ,从而将多层的数据直接统一序列化,而非一个一个序列化:SerializeLayersExample
func SerializeExample(){
	ipv4 := &layers.IPv4{
		SrcIP:      common.SIp,
		DstIP:      common.DIp,
	}
	buffer:=gopacket.NewSerializeBuffer()
	err := ipv4.SerializeTo(buffer, gopacket.SerializeOptions{})
	if err!=nil{
		panic(err)
	}
	log.Println(buffer.Bytes())

}

func SerializeByDifLayerExample(){
	buffer:=gopacket.NewSerializeBuffer()
	option:=gopacket.SerializeOptions{}
	ethernet:=&layers.Ethernet{
		SrcMAC:       common.SMac,
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ethernet.SerializeTo(buffer,option)
	log.Println(buffer.Bytes())
	ipv4:=&layers.IPv4{
		BaseLayer: layers.BaseLayer{},
		Version:   4,
		IHL:       5,
		Length:    12333,
		Protocol:  layers.IPProtocolTCP,
		SrcIP:     common.SIp,
		DstIP:     common.DIp,
		TTL:       64,
	}
	ipv4.SerializeTo(buffer,option)
	log.Println(buffer.Bytes())
	tcp:=&layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(321),
		Window:     2 * 1 << 10,
	}
	tcp.SerializeTo(buffer,option)
	log.Println(buffer.Bytes())
	//packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.DecodeOptions{})
	//flow := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).NetworkFlow()
	//src, dst := flow.Endpoints()
	//log.Printf("from %v to  %v",src.String(),dst.String())
}

func SerializeLayersExample(){
	buffer:=gopacket.NewSerializeBuffer()
	option:=gopacket.SerializeOptions{}
	ethernet:=&layers.Ethernet{
		SrcMAC:       common.SMac,
		DstMAC:       common.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4:=&layers.IPv4{
		BaseLayer: layers.BaseLayer{},
		Version:   4,
		IHL:       5,
		Length:    12333,
		Protocol:  layers.IPProtocolTCP,
		SrcIP:     common.SIp,
		DstIP:     common.DIp,
		TTL:       64,
	}
	tcp:=&layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    layers.TCPPort(123),
		DstPort:    layers.TCPPort(321),
		Window:     2 * 1 << 10,
	}
	gopacket.SerializeLayers(buffer, option, ethernet, ipv4, tcp)
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.DecodeOptions{})
	t:=packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	log.Print(t.TransportFlow().String())
	log.Println(buffer.Bytes())
}
