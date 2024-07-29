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
	UdpPort  string
	TcpPort  string
)

func main() {
	flag.StringVar(&PcapFile, "f", "", "需要加载的数据报文")
	flag.StringVar(&Ip, "i", "", "ip")
	flag.StringVar(&TcpPort, "p", "8888", "tcp port")
	flag.StringVar(&UdpPort, "u", "9999", "udp port")
	flag.Parse()

	if PcapFile == "" {
		flag.Usage()
		return
	}

	tcpaddr := fmt.Sprintf("%s:%s", Ip, TcpPort)
	udpaddr := fmt.Sprintf("%s:%s", Ip, UdpPort)

	tcpConn, err := pcapreplay.NewPcapSrvTcpConn(tcpaddr)
	if err != nil {
		return
	}
	log.Printf("Listen tcp: %v\n", tcpConn)

	udpConn, udpAddr, err := pcapreplay.NewPcapSrvUdpConn(udpaddr)
	if err != nil {
		return
	}
	log.Printf("Listen udp: %v\n", udpConn)

	flows, err := pcapreplay.LoadPcapPayloadFile(PcapFile)
	if err != nil {
		log.Printf("Load Pcap File Failed: %v\n", err)
		return
	}
	log.Printf("Load Pcap[%s] Complete! Flows Num[%d]\n", PcapFile, pcapreplay.GetFlowNum(flows))

	err = pcapreplay.ReplaySrvPcap(flows, tcpConn, udpConn, udpAddr)
	if err != nil {
		log.Printf("Replay Pcap File Failed: %v\n", err)
		return
	}

	return
}
