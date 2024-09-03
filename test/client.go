package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/lishengyu/pcapreplay"
)

var (
	PcapFile string
	Ip       string
	UdpPort  int
	TcpPort  int
	Uuid     string
)

func main() {
	flag.StringVar(&PcapFile, "f", "", "需要加载的数据报文")
	flag.StringVar(&Ip, "i", "127.0.0.1", "ip")
	flag.IntVar(&TcpPort, "p", 8888, "tcp port")
	flag.IntVar(&UdpPort, "u", 9999, "udp port")
	flag.Parse()

	if PcapFile == "" {
		flag.Usage()
		return
	}

	tcpaddr := fmt.Sprintf("%s:%d", Ip, TcpPort)
	udpaddr := fmt.Sprintf("%s:%d", Ip, UdpPort)

	flow, err := pcapreplay.LoadPcapPayloadFile(PcapFile, fmt.Sprintf("uuid:%s\r\n", PcapFile))
	if err != nil {
		log.Printf("Load Pcap File Failed: %v\n", err)
		return
	}
	log.Printf("Load Pcap[%s] Complete!\n", PcapFile)

	err = pcapreplay.ReplayCliPcap(flow, tcpaddr, udpaddr)
	if err != nil {
		log.Printf("Replay Pcap File Failed: %v\n", err)
		return
	}

	return
}
