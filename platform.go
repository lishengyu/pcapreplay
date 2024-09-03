package pcapreplay

import (
	"container/list"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// var UdpConnMap map[*UdpAddr]*FlowInfo
var UdpConnMap sync.Map

type pcapNameMethod func(string) string

func dealPreSrvTcpData(zlog *zap.Logger, conn net.Conn, f pcapNameMethod) (*FlowInfo, error) {
	if conn == nil {
		return nil, fmt.Errorf("conn is nil")
	}

	err := conn.SetReadDeadline(time.Now().Add(ReadDeadline))
	if err != nil {
		return nil, err
	}

	data := make([]byte, RawSocketBuff)
	n, err := conn.Read(data)
	if err != nil {
		return nil, err
	}

	info := string(data[:n])
	if !strings.HasPrefix(info, "uuid:") {
		return nil, fmt.Errorf("the first payload is not start with uuid")
	}

	fs := strings.Split(info, "\r\n")
	uuid := strings.TrimPrefix(fs[0], "uuid:")
	pcapName := f(uuid)
	if pcapName == "" {
		return nil, fmt.Errorf("pcap name is nil")
	}

	return LoadPcapPayloadFile(zlog, pcapName, uuid)
}

func dealPreSrvUdpData(zlog *zap.Logger, data []byte, f pcapNameMethod) (*FlowInfo, error) {
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

	return LoadPcapPayloadFile(zlog, pcapName, uuid)
}

func dealTcpSrvData(zlog *zap.Logger, conn net.Conn, l *list.List) error {
	if conn == nil {
		return nil
	}

	var err error
	var bufferLen int

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
		if bufferLen >= pay.expectlen {
			zlog.Info(fmt.Sprintf("[recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen))
			bufferLen = 0
		} else {
			zlog.Info(fmt.Sprintf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen))
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
			zlog.Info(fmt.Sprintf("[%s:%03d] Send: [%d]\n", FlowDirDesc[pay.dir], pay.pktSeq, pay.len))
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
			zlog.Info(fmt.Sprintf("[recv: %d ==> assembe: %d ==> expect: %d]\n", n, len, pay.expectlen))
			flow.assembLen = 0
		} else {
			flow.assembLen += n
			zlog.Info(fmt.Sprintf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, len, pay.expectlen))
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
			zlog.Info(fmt.Sprintf("Send: [%d]\n", pay.len))
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}
}

func ReplaySrvTcpPcap(zlog *zap.Logger, tcpConn net.Conn, f pcapNameMethod) error {
	flow, err := dealPreSrvTcpData(zlog, tcpConn, f)
	if err != nil {
		zlog.Error(fmt.Sprintf("获取回放报文特征失败：%v\n", err))
		return err
	}

	err = dealTcpSrvData(zlog, tcpConn, flow.list)
	if err != nil {
		zlog.Error(fmt.Sprintf("Flow[%s] Failed: %v\n", flow.tuple, err))
		return err
	}
	zlog.Info(fmt.Sprintf("Replay Flow[%s] Succ!\n", flow.tuple))
	return nil
}

func printRunUdpConn(zlog *zap.Logger) {
	var buff []string
	f := func(key, value interface{}) bool {
		buff = append(buff, key.(string))
		return true
	}
	UdpConnMap.Range(f)
	zlog.Info(fmt.Sprintf("遗留回放任务数量:[%d] 任务详情:%v\n", len(buff), buff))
}

func ReplaySrvUdpPcap(zlog *zap.Logger, udpConn *net.UDPConn, udpAddr *net.UDPAddr, f pcapNameMethod) error {
	defer zlog.Error("udp报文回放异常退出\n")
	data := make([]byte, RawSocketBuff)
	for {
		n, addr, err := udpConn.ReadFromUDP(data)
		if err != nil {
			zlog.Error(fmt.Sprintf("read udp[%v] data failed: %v", addr, err))
			continue
		}
		addrKey := fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
		value, ok := UdpConnMap.Load(addrKey)
		if ok { //已加表
			flow := value.(*FlowInfo)
			err = dealUdpSrvData(zlog, udpConn, flow, addr, n)
			if err == io.EOF {
				zlog.Info(fmt.Sprintf("Replay Flow[%s] Succ: %s\n", flow.tuple, addrKey))
				UdpConnMap.Delete(addrKey)
				printRunUdpConn(zlog)
			} else if err != nil {
				zlog.Error(fmt.Sprintf("Replay Flow[%s] Failed: %s\n", flow.tuple, err))
				UdpConnMap.Delete(addrKey)
				printRunUdpConn(zlog)
			}
		} else { //未加表
			flow, err := dealPreSrvUdpData(zlog, data[:n], f)
			if err != nil {
				zlog.Error(fmt.Sprintf("获取回放报文特征失败：%v\n", err))
				continue
			}
			UdpConnMap.Store(addrKey, flow)
		}
	}
}

func NewPcapSrvTcpConn(addr string) (net.Conn, error) {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Listen tcp failed: %v\n", err)
		return nil, err
	}

	conn, err := listen.Accept()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func NewPcapSrvUdpConn(addr string) (*net.UDPConn, *net.UDPAddr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}

	return conn, udpAddr, nil
}
