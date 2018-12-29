package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go_test/gopacket/examples/capture"



)


var ifaceName =flag.String("f","en0","which interface to sniff on")
var snaplen=flag.Int("l",2048,"limit size of the packet")
var promisc=flag.Bool("p",false,"whether the interface should be  in promis mode")
var timeout=flag.Int64("t",8,"waitting seconds")

func main() {
	flag.Parse()
	capture.PrepareData(*ifaceName,int32(*snaplen),*promisc,time.Duration(time.Duration(*timeout)*time.Second))
	//go captureByPacketSource()
	go captureByHandle()
	signalChan:=make(chan  os.Signal,1)
	signal.Notify(signalChan,syscall.SIGINT,syscall.SIGTERM)
	<-signalChan
	log.Println("exit")
}
func captureByHandle(){
	capture.CaptureThroughHandle()
}
func captureByPacketSource(){
	capture.CaptureThroughPacketSource()
}