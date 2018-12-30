package main

import (
	"log"
	"net"
)

func main() {
	interfaces, _ := net.Interfaces()
	for _,device:=range interfaces{

		if nil==device.HardwareAddr{
			continue
		}

		addrs, _ := device.Addrs()
		if len(addrs)==0{
			continue
		}
		log.Printf("%v:%v",device.Name,device.HardwareAddr)
		for _,addr:=range addrs{
			log.Println(addr.String())
		}
		log.Println("=================")
	}
}