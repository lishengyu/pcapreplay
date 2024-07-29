package pcapreplay

import (
	"container/list"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Stack struct {
	payload []byte
	len     int
	md5     string
	dir     int
}

type FlowInfo struct {
	tuple string
	proto string
	dp    string
	list  *list.List
	num   int
}

type Flows struct {
	flow  []*FlowInfo
	num   int
	exist map[string]int
}

type Stats struct {
	cntSucc int
	cntFail int
}

const (
	FlowDirNone = iota
	FlowDirUp
	FlowDirDn
)

const (
	RawSocketBuff = 2048
	FlowDuration  = 5 * time.Second
	PktDuration   = 100 * time.Millisecond
	ReadDeadline  = 3 * time.Second
	WriteDeadline = 1 * time.Second
	//ReadDeadline = time.Now().Add(3 * time.Second)
)

var (
	FlowDirDesc = map[int]string{
		FlowDirNone: "unknown",
		FlowDirUp:   "up",
		FlowDirDn:   "down",
	}
)

func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func NicList() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("Nic Get Failed: %v\n", err)
		return err
	}

	for i, device := range devices {
		log.Printf("网卡[%d]\n\t%s\n\t%s\n\t%d\n\t%v\n",
			i+1, device.Name, device.Description, device.Flags, device.Addresses)
	}

	return nil
}

func getFlowKey(proto, sip, dip, sp, dp string) string {
	src := fmt.Sprintf("%s-%s", sip, sp)
	dst := fmt.Sprintf("%s-%s", dip, dp)

	tuple := []string{
		src,
		dst,
		proto,
	}

	sort.Strings(tuple)

	return strings.Join(tuple, "|")
}

func getFlowDir(flow *FlowInfo, dp string) int {
	if flow.dp == dp {
		return FlowDirUp
	}
	return FlowDirDn
}

func getPayloadMd5(payload string) string {
	if payload == "" {
		return ""
	}

	m := md5.New()
	io.WriteString(m, payload)
	return fmt.Sprintf("%x", m.Sum(nil))
}

func genPayloadInfo(payload []byte, dir int) Stack {
	md5 := getPayloadMd5(string(payload))
	pay := Stack{
		payload: payload,
		len:     len(payload),
		md5:     md5,
		dir:     dir,
	}
	return pay
}

func NewFlows() *Flows {
	flows := &Flows{
		exist: make(map[string]int),
	}

	return flows
}

func GetFlowNum(flows *Flows) int {
	return flows.num
}

func printFlowsInfo(flows *Flows) {
	for index, flow := range flows.flow {
		log.Printf("流信息:\n")
		log.Printf("流[%d]：%s, 协议：%s, 负载包数量：%d\n", index, flow.tuple, flow.proto, flow.num)
		for e := flow.list.Front(); e != nil; e = e.Next() {
			value := e.Value.(Stack)
			log.Printf("负载和上下行关系：[%s][%d]:[%s]\n", value.md5, value.len, FlowDirDesc[value.dir])
		}
	}
}

func getNetworkLayer(packet gopacket.Packet) (layer gopacket.NetworkLayer) {
	ls := packet.Layers()
	for i, _ := range ls {
		if ls[i].LayerType() == layers.LayerTypeIPv4 {
			layer = ls[i].(*layers.IPv4)
		} else if ls[i].LayerType() == layers.LayerTypeIPv6 {
			layer = ls[i].(*layers.IPv6)
		}
	}

	return layer
}

func getTransportLayer(packet gopacket.Packet) (layer gopacket.TransportLayer) {
	ls := packet.Layers()
	for i, _ := range ls {
		if ls[i].LayerType() == layers.LayerTypeTCP {
			layer = ls[i].(*layers.TCP)
		} else if ls[i].LayerType() == layers.LayerTypeUDP {
			layer = ls[i].(*layers.UDP)
		}
	}

	return layer
}

func getPayloadInfo(packet gopacket.Packet) []byte {
	var buff []byte
	ls := packet.Layers()
	for _, l := range ls {
		if l.LayerType() == layers.LayerTypeTCP || l.LayerType() == layers.LayerTypeUDP {
			buff = l.LayerPayload()
		}
	}

	return buff
}

func updateFlowPayload(flows *Flows, packet gopacket.Packet) {
	/*
		layers := packet.Layers()
		for _, layer := range layers {
			log.Printf("layers: [%d][%v]\n", layer.LayerType(), layer.LayerPayload())
		}
	*/

	L3 := getNetworkLayer(packet)
	L4 := getTransportLayer(packet)
	payload := getPayloadInfo(packet)

	if L3 == nil || L4 == nil {
		//log.Printf("packet L3 or L4 is nil! [%v]\n", packet)
		return
	}
	if len(payload) == 0 {
		//log.Printf("payload is nil! [%v]\n", packet)
		return
	}

	sip := L3.NetworkFlow().Src().String()
	dip := L3.NetworkFlow().Dst().String()
	sp := L4.TransportFlow().Src().String()
	dp := L4.TransportFlow().Dst().String()
	proto := fmt.Sprintf("%v", L4.LayerType())

	key := getFlowKey(proto, sip, dip, sp, dp)
	index, ok := flows.exist[key]
	if ok {
		flow := flows.flow[index]
		pi := genPayloadInfo(payload, getFlowDir(flow, dp))
		flow.list.PushBack(pi)
		flow.num++
	} else {
		flow := &FlowInfo{
			tuple: key,
			proto: proto,
			dp:    dp,
			num:   1,
			list:  list.New(),
		}
		pi := genPayloadInfo(payload, FlowDirUp)
		flow.list.PushBack(pi)

		flows.flow = append(flows.flow, flow)
		flows.exist[key] = flows.num
		flows.num++
	}
}

func LoadPcapPayloadFile(path string) (*Flows, error) {
	flows := NewFlows()

	if exist := pathExists(path); !exist {
		return flows, errors.New(fmt.Sprintf("File [%s] Not exist!\n", path))
	}

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return flows, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		updateFlowPayload(flows, packet)
	}

	//flows := buildFlowsRelation(flowsData)
	printFlowsInfo(flows)
	return flows, nil
}
