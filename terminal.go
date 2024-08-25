package pcapreplay

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

func dealTcpCliData(flow *FlowInfo, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() {
		if err = conn.Close(); err != nil {
			log.Printf("conn Close failed: %v\n", err)
		}
	}()

	l := flow.list
	for {
		if l.Len() == 0 {
			return nil
		}

		front := l.Front()
		if front == nil {
			return nil
		}

		pay := front.Value.(Stack)
		if pay.fake == true {
			return nil
		}

		if pay.dir == FlowDirDn {
			l.Remove(front)
			continue
		}

		_, err = conn.Write(pay.payload)
		if err != nil {
			return err
		}
		log.Printf("[remain: %d]Send: [%d]\n", l.Len(), pay.len)
		l.Remove(front)

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
			if pay.dir == FlowDirUp && pay.expectlen == 0 {
				break
			}

			if pay.dir == FlowDirDn {
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
			if len(buffer) >= pay.expectlen {
				log.Printf("[remain: %d][recv: %d ==> assembe: %d ==> expect: %d]\n", l.Len(), n, len(buffer), pay.expectlen)
				buffer = buffer[:0]
				break
			} else {
				log.Printf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, len(buffer), pay.expectlen)
				continue
			}
		}

		time.Sleep(PktDuration)
	}

	return nil
}

func dealUdpCliData(flow *FlowInfo, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err = conn.Close(); err != nil {
			log.Printf("conn Close failed: %v\n", err)
		}
	}()

	l := flow.list
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

		_, err = conn.Write(pay.payload)
		if err != nil {
			return err
		}
		log.Printf("Send: [%d]\n", pay.len)
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
				log.Printf("length recv[%d], expect[%d], continue...\n", n, pay.len)
				continue
			} else {
				log.Printf("Recv: [%d]\n", pay.len)
				l.Remove(front)
			}
		}

		time.Sleep(PktDuration)
	}

	return err
}

func ReplayCliPcap(flows *Flows, tcpAddr, udpAddr string) error {
	err := errors.New("no flow info")
	nums := len(flows.flow)
	var cnt Stats
	for index, flow := range flows.flow {
		index++
		if flow.proto == "TCP" {
			err = dealTcpCliData(flow, tcpAddr)
		} else if flow.proto == "UDP" {
			err = dealUdpCliData(flow, udpAddr)
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
