package main

import (
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, _:= pcap.FindAllDevs()
	for _,dev:=range devices{
		log.Println(dev.Name)
	}
	log.Println("==============")
	interfaces, _ := net.Interfaces()
	for _,inter:=range interfaces{
		log.Println(inter.Name)
	}

}
