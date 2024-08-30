package pcapreplay

import (
	"container/list"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

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

func dealUdpSrvData(conn *net.UDPConn, l *list.List, udpAddr *net.UDPAddr) error {
	if conn == nil {
		return nil
	}

	var err error
	for {
		if l.Len() == 0 {
			return nil
		}

		front := l.Front()
		if front == nil {
			return nil
		}
		pay := front.Value.(Stack)
		if len(pay.payload) == 0 || pay.dir == FlowDirDn {
			l.Remove(front)
			continue
		}

		err = conn.SetReadDeadline(time.Now().Add(ReadDeadline))
		if err != nil {
			return err
		}

		data := make([]byte, RawSocketBuff)
		n, addr, err := conn.ReadFromUDP(data)
		if err != nil {
			log.Printf("read udp[%v] data failed: %v", addr, err)
			return err
		}
		if n != pay.len {
			log.Printf("length recv mismatch, recv[%d], expect[%d]\n", n, pay.len)
			continue
		}
		log.Printf("Recv: [%d]\n", n)
		l.Remove(front)

		for {
			if l.Len() == 0 {
				return nil
			}

			front := l.Front()
			if front == nil {
				return nil
			}

			pay := front.Value.(Stack)
			if len(pay.payload) == 0 || pay.dir == FlowDirUp {
				break
			}

			_, err = conn.WriteToUDP(pay.payload, addr)
			if err != nil {
				return err
			}
			log.Printf("Send: [%d]\n", pay.len)
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}

	return err
}

func ReplaySrvPcap(flows *Flows, tcpConn net.Conn, udpConn *net.UDPConn, udpAddr *net.UDPAddr) error {
	nums := len(flows.flow)
	var err error
	for index, flow := range flows.flow {
		index++
		if flow.proto == "TCP" {
			err = dealTcpSrvData(tcpConn, flow.list)
		} else if flow.proto == "UDP" {
			err = dealUdpSrvData(udpConn, flow.list, udpAddr)
		} else {
			err = errors.New(fmt.Sprintf("Not Support Proto[%s]\n", flow.proto))
		}

		if err == nil {
			log.Printf("Replay[%d/%d] Flow[%s] Succ!\n", index, nums, flow.tuple)
		} else {
			log.Printf("Replay[%d/%d] Flow[%s] Failed: %v\n", index, nums, flow.tuple, err)
			return err
		}

		//time.Sleep(FlowDuration)
	}

	return nil
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
