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
)

// var UdpConnMap map[*UdpAddr]*FlowInfo
var UdpConnMap sync.Map

type pcapNameMethod func(string) string

func dealPreSrvTcpData(conn net.Conn, f pcapNameMethod) (*FlowInfo, error) {
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

	return LoadPcapPayloadFile(pcapName, uuid)
}

func dealPreSrvUdpData(data []byte, f pcapNameMethod) (*FlowInfo, error) {
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

	return LoadPcapPayloadFile(pcapName, uuid)
}

func dealTcpSrvData(conn net.Conn, l *list.List) error {
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
			log.Printf("[recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen)
			bufferLen = 0
		} else {
			log.Printf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen)
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
			log.Printf("[%s:%03d] Send: [%d]\n", FlowDirDesc[pay.dir], pay.pktSeq, pay.len)
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}
}

func dealUdpSrvData(conn *net.UDPConn, flow *FlowInfo, udpAddr *net.UDPAddr, n int) error {
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
			log.Printf("[recv: %d ==> assembe: %d ==> expect: %d]\n", n, len, pay.expectlen)
			flow.assembLen = 0
		} else {
			flow.assembLen += n
			log.Printf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, len, pay.expectlen)
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
			log.Printf("Send: [%d]\n", pay.len)
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}
}

func ReplaySrvTcpPcap(tcpConn net.Conn, f pcapNameMethod) error {
	flow, err := dealPreSrvTcpData(tcpConn, f)
	if err != nil {
		log.Printf("获取回放报文特征失败：%v\n", err)
		return err
	}

	err = dealTcpSrvData(tcpConn, flow.list)
	if err != nil {
		log.Printf("Flow[%s] Failed: %v\n", flow.tuple, err)
		return err
	}
	log.Printf("Replay Flow[%s] Succ!\n", flow.tuple)
	return nil
}

func printRunUdpConn() {
	var buff []string
	f := func(key, value interface{}) bool {
		buff = append(buff, key.(string))
		return true
	}
	UdpConnMap.Range(f)
	log.Printf("遗留回放任务数量:[%d] 任务详情:%v\n", len(buff), buff)
}

func ReplaySrvUdpPcap(udpConn *net.UDPConn, udpAddr *net.UDPAddr, f pcapNameMethod) error {
	defer log.Printf("udp报文回放异常退出\n")
	data := make([]byte, RawSocketBuff)
	for {
		n, addr, err := udpConn.ReadFromUDP(data)
		if err != nil {
			log.Printf("read udp[%v] data failed: %v", addr, err)
			continue
		}
		addrKey := fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
		value, ok := UdpConnMap.Load(addrKey)
		if ok { //已加表
			flow := value.(*FlowInfo)
			err = dealUdpSrvData(udpConn, flow, addr, n)
			if err == io.EOF {
				log.Printf("Replay Flow[%s] Succ: %s\n", flow.tuple, addrKey)
				UdpConnMap.Delete(addrKey)
				printRunUdpConn()
			} else if err != nil {
				log.Printf("Replay Flow[%s] Failed: %v\n", flow.tuple, err)
				UdpConnMap.Delete(addrKey)
				printRunUdpConn()
			}
		} else { //未加表
			flow, err := dealPreSrvUdpData(data[:n], f)
			if err != nil {
				log.Printf("获取回放报文特征失败：%v\n", err)
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
