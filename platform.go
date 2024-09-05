package pcapreplay

import (
	"container/list"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// var UdpConnMap map[*UdpAddr]*FlowInfo
var UdpConnMap sync.Map

type pcapNameMethod func(string) string

func dealPreSrvTcpData(zlog *zap.Logger, conn net.Conn, f pcapNameMethod) (int, *FlowInfo, error) {
	if conn == nil {
		return 0, nil, fmt.Errorf("conn is nil")
	}

	err := conn.SetReadDeadline(time.Now().Add(ReadDeadline))
	if err != nil {
		return 0, nil, err
	}

	data := make([]byte, RawSocketBuff)
	n, err := conn.Read(data)
	if err != nil {
		return 0, nil, err
	}

	info := string(data[:n])
	if !strings.HasPrefix(info, "uuid:") {
		return 0, nil, fmt.Errorf("the first payload is not start with uuid")
	}

	fs := strings.SplitN(info, "\r\n", 2)
	if len(fs) != 2 {
		return 0, nil, fmt.Errorf("uuid not end with '\r\n'")
	}

	uuid := strings.TrimPrefix(fs[0], "uuid:")
	pcapName := f(uuid)
	if pcapName == "" {
		return 0, nil, fmt.Errorf("pcap name is nil")
	}

	preSize := len(fs[1])
	zlog.Info("tcp回放开始", zap.String("uuid", uuid), zap.String("pcap", pcapName), zap.String("conn", conn.RemoteAddr().String()), zap.Int("preSize", preSize))

	flow, err1 := LoadPcapPayloadFile(zlog, pcapName, uuid)
	return preSize, flow, err1
}

func dealPreSrvUdpData(zlog *zap.Logger, data []byte, addr string, f pcapNameMethod) (*FlowInfo, error) {
	info := string(data)

	if !strings.HasPrefix(info, "uuid:") {
		return nil, fmt.Errorf("%s the first payload is not start with uuid", info)
	}

	fs := strings.Split(info, "\r\n")
	uuid := strings.TrimPrefix(fs[0], "uuid:")
	pcapName := f(uuid)
	if pcapName == "" {
		return nil, fmt.Errorf("pcap name is nil")
	}

	zlog.Info("udp回放开始", zap.String("uuid", uuid), zap.String("pcap", pcapName), zap.String("conn", addr))
	return LoadPcapPayloadFile(zlog, pcapName, uuid)
}

func dealTcpSrvData(zlog *zap.Logger, conn net.Conn, l *list.List, prelen int) error {
	if conn == nil {
		return nil
	}

	var err error
	var bufferLen int

	//前面粘包，导致有部分字节内容已经收取过了
	bufferLen = prelen

	for {
		if l.Len() == 0 {
			return nil
		}

		front := l.Front()
		if front == nil {
			return nil
		}
		pay := front.Value.(Stack)
		if pay.dir == FlowDirUp {
			l.Remove(front)
			continue
		}

		//处理前面粘包，已经收全的场景
		if bufferLen >= pay.expectlen {
			zlog.Info("tcp报文接收", zap.String("conn", conn.RemoteAddr().String()), zap.Int("pre_recv", bufferLen), zap.Int("expect", pay.expectlen))
			bufferLen = 0
		} else {
			zlog.Info("tcp报文接收", zap.String("conn", conn.RemoteAddr().String()), zap.Int("pre_recv continue", bufferLen), zap.Int("expect", pay.expectlen))
			err = conn.SetReadDeadline(time.Now().Add(ReadDeadline))
			if err != nil {
				return err
			}

			data := make([]byte, RawSocketBuff)
			n, err := conn.Read(data)
			if err != nil {
				return err
			}

			bufferLen += n
			continue
		}

		//读完结束
		if pay.fake {
			return nil
		}

		for {
			if l.Len() == 0 {
				return nil
			}

			front := l.Front()
			if front == nil {
				return nil
			}

			pay := front.Value.(Stack)
			if pay.dir == FlowDirUp {
				break
			}

			//此处肯定是下行数据
			_, err = conn.Write(pay.payload)
			if err != nil {
				return err
			}
			zlog.Info("tcp报文发送", zap.String("conn", conn.RemoteAddr().String()), zap.String("方向", FlowDirDesc[pay.dir]),
				zap.Int("索引", pay.pktSeq), zap.Int("发送长度", pay.len))
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}
}

func dealUdpSrvData(zlog *zap.Logger, conn *net.UDPConn, flow *FlowInfo, udpAddr *net.UDPAddr, n int) error {
	if conn == nil {
		return nil
	}

	var err error
	l := flow.list
	for {
		if l.Len() == 0 {
			return io.EOF
		}

		front := l.Front()
		if front == nil {
			return io.EOF
		}

		pay := front.Value.(Stack)
		if pay.dir == FlowDirUp {
			l.Remove(front)
			continue
		}

		len := flow.assembLen + n
		if len >= pay.expectlen {
			zlog.Info("udp报文接收", zap.String("conn", udpAddr.String()), zap.Int("recv", n), zap.Int("assembe", len), zap.Int("expect", pay.expectlen))
			flow.assembLen = 0
		} else {
			flow.assembLen += n
			zlog.Info("udp报文接收", zap.String("conn", udpAddr.String()), zap.Int("recv continue", n), zap.Int("assembe", len), zap.Int("expect", pay.expectlen))
			return nil
		}

		//读完结束
		if pay.fake {
			return io.EOF
		}

		for {
			if l.Len() == 0 {
				return io.EOF
			}

			front := l.Front()
			if front == nil {
				return io.EOF
			}

			pay := front.Value.(Stack)
			if pay.dir == FlowDirUp {
				if pay.fake {
					return io.EOF
				} else {
					//写结束，需要等待接受
					return nil
				}
			}

			_, err = conn.WriteToUDP(pay.payload, udpAddr)
			if err != nil {
				return err
			}
			zlog.Info("udp报文发送", zap.String("conn", udpAddr.String()), zap.String("方向", FlowDirDesc[pay.dir]),
				zap.Int("索引", pay.pktSeq), zap.Int("发送长度", pay.len))
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}
}

func ReplaySrvTcpPcap(zlog *zap.Logger, tcpConn net.Conn, f pcapNameMethod) error {
	preSize, flow, err := dealPreSrvTcpData(zlog, tcpConn, f)
	if err != nil {
		zlog.Error("结束tcp回放", zap.Error(err))
		return err
	}

	err = dealTcpSrvData(zlog, tcpConn, flow.list, preSize)
	if err != nil {
		zlog.Error("结束tcp回放", zap.String("conn", tcpConn.RemoteAddr().String()), zap.Error(err))
		return err
	}
	zlog.Error("结束tcp回放", zap.String("conn", tcpConn.RemoteAddr().String()))
	return nil
}

func printRunUdpConn(zlog *zap.Logger) {
	var buff []string
	f := func(key, value interface{}) bool {
		buff = append(buff, key.(string))
		return true
	}
	UdpConnMap.Range(f)
	zlog.Info("udp报文回放任务详情", zap.Int("任务数量", len(buff)), zap.Strings("任务详情", buff))
}

func ReplaySrvUdpPcap(zlog *zap.Logger, udpConn *net.UDPConn, udpAddr *net.UDPAddr, f pcapNameMethod) error {
	defer zlog.Error("udp报文回放异常退出")
	data := make([]byte, RawSocketBuff)
	for {
		n, addr, err := udpConn.ReadFromUDP(data)
		if err != nil {
			zlog.Error("ReadFromUDP失败", zap.String("addr", addr.String()), zap.Error(err))
			continue
		}
		addrKey := fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
		value, ok := UdpConnMap.Load(addrKey)
		if ok { //已加表
			flow := value.(*FlowInfo)
			err = dealUdpSrvData(zlog, udpConn, flow, addr, n)
			if err == io.EOF {
				zlog.Error("结束udp回放", zap.String("tuple", flow.tuple), zap.String("conn", addrKey))
				UdpConnMap.Delete(addrKey)
				printRunUdpConn(zlog)
			} else if err != nil {
				zlog.Error("结束udp回放", zap.String("tuple", flow.tuple), zap.String("conn", addrKey), zap.Error(err))
				UdpConnMap.Delete(addrKey)
				printRunUdpConn(zlog)
			}
		} else { //未加表
			flow, err := dealPreSrvUdpData(zlog, data[:n], addrKey, f)
			if err != nil {
				zlog.Error("结束udp回放", zap.String("tuple", flow.tuple), zap.String("conn", addrKey), zap.Error(err))
				continue
			}
			UdpConnMap.Store(addrKey, flow)
		}
	}
}
