package main

import (
	"flag"
	"go_test/gopacket_examples"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"


)


var ifaceName =flag.String("f","en0","captured from which interface")
var snaplen=flag.Int("l",2048,"limit size of the packet")
var promisc=flag.Bool("p",false,"whether the interface should be  in promis mode")
var timeout=flag.Int64("t",8,"waitting seconds")

func main() {
	flag.Parse()
	gopacket_examples.PrepareData(*ifaceName,int32(*snaplen),*promisc,time.Duration(time.Duration(*timeout)*time.Second))
	//go captureByPacketSource()
	go captureByHandle()
	signalChan:=make(chan  os.Signal,1)
	signal.Notify(signalChan,syscall.SIGINT,syscall.SIGTERM)
	<-signalChan
	log.Println("exit")
}
func captureByHandle(){
	gopacket_examples.CaptureThroughHandle()
}
func captureByPacketSource(){
	gopacket_examples.CaptureThroughPacketSource()
}