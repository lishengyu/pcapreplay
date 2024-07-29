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
		if len(pay.payload) == 0 || pay.dir == FlowDirDn {
			l.Remove(front)
			continue
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
			n, err := conn.Read(data)
			if err != nil {
				return err
			}
			md5 := getPayloadMd5(string(data[:n]))
			if md5 != pay.md5 {
				log.Printf("md5 recv mismatch, recv[%s], expect[%s]\n", md5, pay.md5)
				log.Printf("length[%d][%v]\n", n, data[:n])
				continue
			}
			log.Printf("Recv: [%s]\n", md5)
			l.Remove(front)
		}

		time.Sleep(PktDuration)
	}

	return err
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

			buffer = append(buffer, data[:n]...)
			if len(buffer) < pay.len {
				log.Printf("length recv less, recv[%d], expect[%d], continue...\n", len(buffer), pay.len)
				buffer = append(buffer, data[:n]...)
				continue
			} else if len(buffer) > pay.len {
				log.Printf("length recv mismatch, recv[%d], expect[%d]\n", len(buffer), pay.len)
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
		}

		time.Sleep(PktDuration)
	}

	return err
}

func ReplayCliPcap(flows *Flows, addr string) error {
	err := errors.New("no flow info")
	nums := len(flows.flow)
	var cnt Stats
	for index, flow := range flows.flow {
		index++
		if flow.proto == "TCP" {
			err = dealTcpCliData(flow, addr)
		} else if flow.proto == "UDP" {
			err = dealUdpCliData(flow, addr)
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
