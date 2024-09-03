package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/lishengyu/pcapreplay"
	"go.uber.org/zap"
)

var (
	Ip      string
	UdpPort int
	TcpPort int
)

func getPcapName(uuid string) string {
	return uuid
}

func main() {
	flag.StringVar(&Ip, "i", "127.0.0.1", "ip")
	flag.IntVar(&TcpPort, "p", 0, "tcp port")
	flag.IntVar(&UdpPort, "u", 0, "udp port")
	flag.Parse()

	if TcpPort == 0 && UdpPort == 0 {
		flag.Usage()
		return
	}

	// 创建一个新的日志记录器
	zlog, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer zlog.Sync() // 确保缓冲的日志写入

	if TcpPort != 0 {
		tcpaddr := fmt.Sprintf("%s:%d", Ip, TcpPort)
		log.Printf("Listen tcp: %v\n", tcpaddr)

		listen, err := net.Listen("tcp", tcpaddr)
		if err != nil {
			log.Printf("Listen tcp failed: %v\n", err)
			return
		}

		for {
			conn, err := listen.Accept()
			if err != nil {
				log.Printf("Accept failed: %v\n", err)
				continue
			}

			go pcapreplay.ReplaySrvTcpPcap(zlog, conn, getPcapName)
		}
	} else if UdpPort != 0 {
		udpaddr := fmt.Sprintf("%s:%d", Ip, UdpPort)
		log.Printf("Listen udp: %v\n", udpaddr)

		addr, err := net.ResolveUDPAddr("udp", udpaddr)
		if err != nil {
			log.Printf("ResolveUDPAddr failed: %v\n", err)
			return
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Printf("ListenUDP failed: %v\n", err)
			return
		}
		defer conn.Close()
		pcapreplay.ReplaySrvUdpPcap(zlog, conn, addr, getPcapName)
	}

	return
}
