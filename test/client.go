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
	TcpPort  string
	UdpPort  string
)

func main() {
	flag.StringVar(&PcapFile, "f", "", "需要加载的数据报文")
	flag.StringVar(&Ip, "i", "127.0.0.1", "ip")
	flag.StringVar(&TcpPort, "p", "8888", "tcp port")
	flag.StringVar(&UdpPort, "u", "9999", "udp port")
	flag.Parse()

	if PcapFile == "" {
		flag.Usage()
		return
	}

	tcpaddr := fmt.Sprintf("%s:%s", Ip, TcpPort)
	udpaddr := fmt.Sprintf("%s:%s", Ip, UdpPort)

	flows, err := pcapreplay.LoadPcapPayloadFile(PcapFile)
	if err != nil {
		log.Printf("Load Pcap File Failed: %v\n", err)
		return
	}
	log.Printf("Load Pcap[%s] Complete! Flows Num[%d]\n", PcapFile, pcapreplay.GetFlowNum(flows))

	err = pcapreplay.ReplayCliPcap(flows, tcpaddr, udpaddr)
	if err != nil {
		log.Printf("Replay Pcap File Failed: %v\n", err)
		return
	}

	return
}
