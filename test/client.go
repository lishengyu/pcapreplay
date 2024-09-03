package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/lishengyu/pcapreplay"
	"go.uber.org/zap"
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

	// 创建一个新的日志记录器
	zlog, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer zlog.Sync() // 确保缓冲的日志写入

	tcpaddr := fmt.Sprintf("%s:%d", Ip, TcpPort)
	udpaddr := fmt.Sprintf("%s:%d", Ip, UdpPort)

	flow, err := pcapreplay.LoadPcapPayloadFile(zlog, PcapFile, fmt.Sprintf("uuid:%s\r\n", PcapFile))
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
