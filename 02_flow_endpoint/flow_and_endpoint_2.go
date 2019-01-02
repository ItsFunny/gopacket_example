package _2_flow_endpoint

import (
	"encoding/json"
	"go_test/examples/gopacket/common"
	"log"

	"github.com/google/gopacket/layers"

	"go_test/examples/gopacket/01_packet"
)

// flow 包含 2个endPoint 分别代表src和dst
// flow 对于不同层有不同的含义
// 对于LinkLayer 链路层而言 src,dst代表 代表mac地址
// 对于NetWorkLayer 网络层而言 代表ip地址
// 而对于TransportLayer 传输层而言 代表端口号
// 但是以上都是基于已有数据而言,如错误示例:WrongLayerExample

// flow ,endpoint成员属性: 顾名思义 即可

// 核心功能:
// flow 和 endpoint 可以作为map中的key,也就代表着可以搜集特定的packet,如示例CollectPacket
// 并且双方内部的fasthash使得对于flow 能够保证 A->B与B->A的hash值是相同的
// 	也就代表着可以忽略双方的交互信息,省略'废话',可以生成联系图 ,如 FIXME



func WrongLayerExample(){
	bytes:=common.SMac
	bytes=append(bytes,common.DMac...)
	marshal, _ := json.Marshal(layers.LayerTypeIPv4)
	bytes=append(bytes,marshal...)
	option:= _1_packet.CreateDecodeOption(false,false,false,false)
	packet := _1_packet.CreatePacket(bytes, option)
	// packet本身只包装了LinkLayer 却获取NetWrokLayer ,nil 异常
	flow := packet.NetworkLayer().NetworkFlow()
	src, dst := flow.Endpoints()
	log.Println(src.String())
	log.Println(dst.String())
}

func SuccessLayerExample(){
	bytes:=common.SMac
	bytes=append(bytes,common.DMac...)
	marshal, _ := json.Marshal(layers.LayerTypeIPv4)
	bytes=append(bytes,marshal...)
	option:= _1_packet.CreateDecodeOption(false,false,false,false)
	packet := _1_packet.CreatePacket(bytes, option)
	flow := packet.LinkLayer().LinkFlow()
	src, dst := flow.Endpoints()
	log.Printf("from mac %v: to mac : %v:",src.String(),dst.String())
	log.Println(flow.EndpointType())
}
