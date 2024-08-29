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
	flag.StringVar(&TcpPort, "p", "", "tcp port")
	flag.StringVar(&UdpPort, "u", "", "udp port")
	flag.Parse()

	if PcapFile == "" {
		flag.Usage()
		return
	}

	if TcpPort != "" {
		tcpaddr := fmt.Sprintf("%s:%s", Ip, TcpPort)
		log.Printf("Listen tcp: %v\n", tcpaddr)

		tcpConn, err := pcapreplay.NewPcapSrvTcpConn(tcpaddr)
		if err != nil {
			log.Printf("Failed: %v\n", err)
			return
		}
		defer tcpConn.Close()

		flows, err := pcapreplay.LoadPcapPayloadFile(PcapFile)
		if err != nil {
			log.Printf("Failed: Load Pcap File: %v\n", err)
			return
		}
		log.Printf("Load Pcap[%s] Complete! Flows Num[%d]\n", PcapFile, pcapreplay.GetFlowNum(flows))

		err = pcapreplay.ReplaySrvPcap(flows, tcpConn, nil, nil)
		if err != nil {
			log.Printf("Failed: Replay Pcap File: %v\n", err)
			return
		}
	} else if UdpPort != "" {
		udpaddr := fmt.Sprintf("%s:%s", Ip, UdpPort)
		log.Printf("Listen udp: %v\n", udpaddr)
		udpConn, udpAddr, err := pcapreplay.NewPcapSrvUdpConn(udpaddr)
		if err != nil {
			log.Printf("Failed: %v\n", err)
			return
		}
		defer udpConn.Close()

		flows, err := pcapreplay.LoadPcapPayloadFile(PcapFile)
		if err != nil {
			log.Printf("Failed: Load Pcap File: %v\n", err)
			return
		}
		log.Printf("Load Pcap[%s] Complete! Flows Num[%d]\n", PcapFile, pcapreplay.GetFlowNum(flows))

		err = pcapreplay.ReplaySrvPcap(flows, nil, udpConn, udpAddr)
		if err != nil {
			log.Printf("Failed: Replay Pcap File: %v\n", err)
			return
		}
	}

	return
}
