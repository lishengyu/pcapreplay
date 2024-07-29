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
	Port     string
)

func main() {
	flag.StringVar(&PcapFile, "f", "", "需要加载的数据报文")
	flag.StringVar(&Ip, "i", "127.0.0.1", "ip")
	flag.StringVar(&Port, "p", "8888", "port")
	flag.Parse()

	if PcapFile == "" {
		flag.Usage()
		return
	}

	flows, err := pcapreplay.LoadPcapPayloadFile(PcapFile)
	if err != nil {
		log.Printf("Load Pcap File Failed: %v\n", err)
		return
	}
	log.Printf("Load Pcap[%s] Complete! Flows Num[%d]\n", PcapFile, pcapreplay.GetFlowNum(flows))

	addr := fmt.Sprintf("%s:%s", Ip, Port)
	err = pcapreplay.ReplayCliPcap(flows, addr)
	if err != nil {
		log.Printf("Replay Pcap File Failed: %v\n", err)
		return
	}

	return
}
