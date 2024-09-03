package pcapreplay

import (
	"fmt"
	"net"
	"time"

	"github.com/lishengyu/slog"
)

func dealTcpCliData(flow *FlowInfo, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() {
		if err = conn.Close(); err != nil {
			slog.Warn(fmt.Sprintf("conn Close failed: %v\n", err))
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
		//伪节点，需要接收，不需要发送数据
		if pay.fake {
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
		slog.Info(fmt.Sprintf("[%s:%03d] Send: [%d]\n", FlowDirDesc[pay.dir], pay.pktSeq, pay.len))
		l.Remove(front)

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
			if pay.dir == FlowDirDn {
				l.Remove(front)
				continue
			}

			//非状态切换后的首个payload报文，只需要负责发送
			if pay.expectlen == 0 {
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

			bufferLen += n
			if bufferLen >= pay.expectlen {
				slog.Info(fmt.Sprintf("[recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen))
				bufferLen = 0
				break
			} else {
				slog.Info(fmt.Sprintf("continue reading... [recv: %d ==> assembe: %d ==> expect: %d]\n", n, bufferLen, pay.expectlen))
				continue
			}
		}

		time.Sleep(PktDuration)
	}
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
			slog.Warn(fmt.Sprintf("conn Close failed: %v\n", err))
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
		slog.Info(fmt.Sprintf("Send: [%d]\n", pay.len))
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
				slog.Warn(fmt.Sprintf("read udp[%v] data failed: %v", addr, err))
				return err
			}

			if n != pay.len {
				slog.Warn(fmt.Sprintf("length recv[%d], expect[%d], continue...\n", n, pay.len))
				continue
			} else {
				slog.Info(fmt.Sprintf("Recv: [%d]\n", pay.len))
				l.Remove(front)
			}
		}

		time.Sleep(PktDuration)
	}
}

func ReplayCliPcap(flow *FlowInfo, tcpAddr, udpAddr string) error {
	var err error
	if flow.proto == "TCP" {
		err = dealTcpCliData(flow, tcpAddr)
	} else if flow.proto == "UDP" {
		err = dealUdpCliData(flow, udpAddr)
	} else {
		err = fmt.Errorf(fmt.Sprintf("Not Support Proto[%s]\n", flow.proto))
	}

	if err != nil {
		slog.Warn(fmt.Sprintf("Replay Flow[%s] Fail! %v\n", flow.tuple, err))
		return err
	}

	slog.Info(fmt.Sprintf("Replay Flow[%s] Succ!\n", flow.tuple))
	return nil
}
