## 示例程序:

2个示例程序:一个用于抓包,一个用于随机发包
运行capture_main.go 或者sender_main.go
部分详细代码在各目录下

## npcap

winpcap的进阶版,winpcap已经停止维护

## 安装

* 从https://nmap.org/npcap/#download 下载 npcap 以及npcap sdk
* 解压sdk到C:/WpdPack/ 下,原因在于pcap.go中默认指向了这个文件夹

- 1.Packet
    -   1.1 快速创建Packet: gopacket#NewPacket
    -   1.2 Decode
- 2.Flow And Endpoint 
    -    Flow 流量,包含srcEndPoint 和dstEndPoint 表明是谁发给谁
    -    EndPoint 
- 3.Decoder
    -   3.1 自定义decoder
    -   3.2 DecodingLayerParser 对特定的layer解码,大大提升效率
- 4.Serialize

## 抓包

- 关于抓包,有两种方式 ,两种方式的区别在于:handle获取到的数据是字节码
而packetSource捕获包中调用的函数其实无二,但是多了一层封装而已(即将原数据映射成为了实体)
   -    handle的抓包调用链:
   handle#ZeroCopyReadPacketData/ReadPacketData-><br>
   handle#getNextBufPtrLocked-> return error<br>
   handle error -> <br>
   return bytes<br>
   -    packetSource的抓包调用链
   packetSource#NextPacket-><br>
   handle#ReadPacket-><br>
   handle#getNextBufPtrLocked-> return err<br>
   handle error-> <br>
   NewPacket->(包装数据)<br>
   return Packet
    
- 1.通过handle的形式<br>
    - 1.1创建handle有两种方式
 	    -   1.1.1 通过函数传多个参数创建
 		-   1.1.2 通过第三者初始化设置,可以起到定制的作用
	- 1.2 配合BPF过滤抓取特定的包
		-   1.2.1 简单通过配合handle#SetBPFFilter实现
		-   1.2.2 handle#NewBPF 通过返回的BPF#Match与CaptureInfo进行匹配过滤 //需要人为控制
		-   1.2.3 通过BpfInstruction 方式,这个与afpacket中的RawInstruction类似,可以通过bpf_util实现rawInstruction与Instruction互转
	- 1.3 handle抓包函数与afpacket类似,底层有相同的代码块,ZeroCopyReadPacketData或者ReadPacketData抓取<br>
	若用handle抓包的话还需要提供实现了Decocer接口的对象<br>
	可参考:<br>
        &emsp;packet.go NewPacket L652 <br>
        &emsp;packet.go packetSource#NewPacket L798 <br>
        &emsp;enums.go layers.LinkTypeXXX都实现了这个接口 L100 <br> 
	- 1.4 通过handle#Stats获取packets相关信息,接收包的总数等信息,**若通过packetSource则额外需要定义这个变量**
- 2.通过PacketSource的形式
 	- 2.1 packetSource的创建需要通过handle
	- 2.2 通过PacketSource抓包有两种方式
        -  2.2.1 第一种是通过packetSource#Packets 返回的是一个chan packet类型,这也是最便利最简单的方式
				  但是这种方式无法控制,error之类的也直接全丢弃不管
		-  2.2.2 通过packetSource#NextPacket ,这种方法最灵活,同时外抛了异常,同时当流量小的时候性能很高(没有
				  chan的开销)
				  
## 异常处理

- 见 pcap.go L327 && L387 
    -   io.EOF : file or OpenOffLine  当无数据读取的时候,不会返回指定的error,统一io.EOF 
    -   NextErrorNotActivated : 
    -   NextErrorTimeoutExpired : 超时
    -   NextErrorReadError : 读取错误,packet有误