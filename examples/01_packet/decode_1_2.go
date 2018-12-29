package _1_packet

import "github.com/google/gopacket"

func CreateDecodeOption(lazy,nocpy,skilError,streamAsDgm bool)gopacket.DecodeOptions {
	return gopacket.DecodeOptions{
		// 只在第一次被调用的时候才decode
		Lazy:                     lazy,
		// 是否拷贝传入的data数据,true会提升性能,当然在数据确保不会变的前提
		NoCopy:                   nocpy,
		// 内部是通过调用再次调用addFinalDecodeError 这个函数
		// 主要是为了防止panic ,其余情况都已经通过error来判断是否成功
		// 当创建包失败的时候会判断,若为true则会调用recover函数,recover函数之后则会生成一个错误的packet
		// 判断packet创建是否成功需要通过errorLayer: 见packet.go L195 && L183
		SkipDecodeRecovery:       skilError,
		// 这个不是很理解 FIXME 复现用例
		DecodeStreamsAsDatagrams: streamAsDgm,
	}
}
