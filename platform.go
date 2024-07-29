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
	var err error
	buffer := make([]byte, 0)

	for {
		if l.Len() == 0 {
			return nil
		}

		front := l.Front()
		if front == nil {
			return nil
		}
		pay := front.Value.(Stack)
		if pay.len == 0 || pay.dir == FlowDirDn {
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

		buffer = append(buffer, data[:n]...)
		log.Printf("%d ==> %d | %d\n", n, len(buffer), pay.len)
		if len(buffer) < pay.len {
			log.Printf("length recv less, recv[%d], expect[%d], continue...\n", len(buffer), pay.len)
			continue
		} else if len(buffer) > pay.len {
			log.Printf("length recv oversize, recv[%d], expect[%d], dropped!!\n", len(buffer), pay.len)
			buffer = buffer[:0]
			continue
		} else { //len(buffer) == pay.len
			md5 := getPayloadMd5(string(buffer))
			if md5 != pay.md5 {
				log.Printf("md5 recv mismatch, recv[%d][%s], expect[%d][%s]\n", n, md5, pay.len, pay.md5)
				buffer = buffer[:0]
				continue
			} else {
				buffer = buffer[:0]
				log.Printf("Recv: [%s]\n", md5)
				l.Remove(front)
			}
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
			if pay.len == 0 || pay.dir == FlowDirUp {
				break
			}

			err = conn.SetWriteDeadline(time.Now().Add(WriteDeadline))
			if err != nil {
				return err
			}

			_, err = conn.Write(pay.payload)
			if err != nil {
				return err
			}
			log.Printf("Send: [%s]\n", pay.md5)
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}

	return err
}

func dealUdpSrvData(conn *net.UDPConn, l *list.List, udpAddr *net.UDPAddr) error {
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
		md5 := getPayloadMd5(string(data[:n]))
		if md5 != pay.md5 {
			log.Printf("md5 recv mismatch, recv[%s], expect[%s]\n", md5, pay.md5)
			continue
		}
		log.Printf("Recv: [%s]\n", md5)
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

			err = conn.SetWriteDeadline(time.Now().Add(WriteDeadline))
			if err != nil {
				return err
			}

			_, err = conn.WriteToUDP(pay.payload, addr)
			if err != nil {
				return err
			}
			log.Printf("Send: [%s]\n", pay.md5)
			l.Remove(front)
			time.Sleep(PktDuration)
		}
	}

	return err
}

func ReplaySrvPcap(flows *Flows, tcpConn net.Conn, udpConn *net.UDPConn, udpAddr *net.UDPAddr) error {
	err := errors.New("no flow info")
	nums := len(flows.flow)
	var cnt Stats
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
			cnt.cntSucc++
			log.Printf("Replay[%d/%d] Flow[%s] Succ!\n", index, nums, flow.tuple)
		} else {
			cnt.cntFail++
			log.Printf("Replay[%d/%d] Flow[%s] Fail! %v\n", index, nums, flow.tuple, err)
		}

		time.Sleep(FlowDuration)
	}

	log.Printf("Sum:%d, succ:%d, fail:%d\n", nums, cnt.cntSucc, cnt.cntFail)
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
