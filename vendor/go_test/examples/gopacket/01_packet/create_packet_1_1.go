package _1_packet

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 调用链:
// func:返回一个packet(依各层的定义而定)
// 第一个参数:data 代表的是这个包的数据
// 第二个参数:firstLayerDecoder 代表的是可以通过哪层的格式decode
//		因为layers.LayerTypeXXX 都实现了decoder接口,同时内部是通过数组(0~2000) 或者是map(小于0或者>2000)
// 		来获取decoder的  见 layertype.go L90
// 第三个参数: options 见decode_1_2
func CreatePacket(bytes []byte,options gopacket.DecodeOptions) gopacket.Packet {

	packet := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, options)
	return packet
}
