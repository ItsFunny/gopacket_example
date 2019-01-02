package main

import (
	"flag"
	"log"
	"net"

	"go_test/examples/capture"
)


var dstIp = flag.String("d", "120.78.240.211", "dstIp")
var iface = flag.String("i", "awdl0", "")
var sendTimes = flag.Int("s", 5, "amount of packets to be sent")
var interval = flag.Int64("t", 1, "send interval")


var applicationChan chan struct{}


func main() {
	flag.Parse()
	dIp := net.ParseIP(*dstIp)
	if dIp == nil {
		log.Println("无效ip")
		flag.Usage()
		return
	}
	capture.InitData(dIp, *sendTimes, *interval)
	if *iface == "any" {
		capture.SendFromAny()
	} else {
		ip, sMac := getLocalIpByName(*iface)
		if ip == nil || sMac == nil {
			log.Println("cant get local ip,check the interfaceName,send from local interfaces")
			capture.SendFromAny()
		}else{
			capture.SendFromConcrete(*iface)
		}
	}
	log.Println("exit")
}
func getLocalIpByName(iface string) (net.IP, net.HardwareAddr) {
	ifs, e := net.Interfaces()
	if nil != e {
		log.Fatalf("cant get local interfaces,error:%v", e)
	}
	for _, it := range ifs {
		if it.Name != iface {
			continue
		}
		addrs, _ := it.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if nil == ipnet.IP.To4() {
					continue
				}
				return ipnet.IP, it.HardwareAddr
			}
		}
	}
	return nil, nil
}


