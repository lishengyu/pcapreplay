package main

import (
	"flag"
	"fmt"
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
		zlog.Info("Listen tcp", zap.String("addr", tcpaddr))

		listen, err := net.Listen("tcp", tcpaddr)
		if err != nil {
			zlog.Error("Listen tcp failed", zap.String("addr", tcpaddr), zap.Error(err))
			return
		}

		for {
			conn, err := listen.Accept()
			if err != nil {
				zlog.Error("Accept failed:", zap.String("addr", tcpaddr), zap.Error(err))
				continue
			}

			go pcapreplay.ReplaySrvTcpPcap(zlog, conn, getPcapName)
		}
	} else if UdpPort != 0 {
		udpaddr := fmt.Sprintf("%s:%d", Ip, UdpPort)
		zlog.Info("Listen udp", zap.String("addr", udpaddr))

		addr, err := net.ResolveUDPAddr("udp", udpaddr)
		if err != nil {
			zlog.Error("ResolveUDPAddr failed", zap.String("addr", udpaddr), zap.Error(err))
			return
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			zlog.Error("ListenUDP failed", zap.String("addr", udpaddr), zap.Error(err))
			return
		}
		defer conn.Close()
		pcapreplay.ReplaySrvUdpPcap(zlog, conn, addr, getPcapName)
	}

	return
}
