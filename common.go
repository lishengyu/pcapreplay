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
}

type Flows struct {
	flow      []*FlowInfo
	num       int
	assembPay []byte
	assembDir int
	exist     map[string]int
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
	ReadDeadline  = 20 * time.Second
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

func newFlow(key, proto, dp string) *FlowInfo {
	flow := &FlowInfo{
		tuple: key,
		proto: proto,
		dp:    dp,
		list:  list.New(),
	}
	return flow
}

func newStack(payload []byte, dir int) Stack {
	md5 := getPayloadMd5(string(payload))
	pay := Stack{
		payload: payload,
		len:     len(payload),
		md5:     md5,
		dir:     dir,
	}
	return pay
}

func appendFlows(flows *Flows, flow *FlowInfo, key string) {
	flows.flow = append(flows.flow, flow)
	flows.exist[key] = flows.num
	flows.num++
}

// 重置重组信息
func setAssembInfo(flows *Flows, dir int, payload []byte) {
	flows.assembDir = dir
	flows.assembPay = payload
}

// 更新重组信息
func upAssembInfo(flows *Flows, payload []byte) {
	flows.assembPay = append(flows.assembPay, payload...)
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
		log.Printf("流[%d]：%s, 协议：%s, 负载包数量：%d\n", index, flow.tuple, flow.proto, flow.list.Len())
		var index int
		for e := flow.list.Front(); e != nil; e = e.Next() {
			value := e.Value.(Stack)
			index++
			log.Printf("负载和上下行关系：[%d][%s][%d]:[%s]\n", index, value.md5, value.len, FlowDirDesc[value.dir])
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
		return
	}
	if len(payload) == 0 {
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
		curDir := getFlowDir(flow, dp)
		if flows.assembDir != curDir { //上下行切换，入队列
			setAssembInfo(flows, curDir, payload)
			pi := newStack(payload, curDir)
			flow.list.PushBack(pi)
		} else {
			//同方向，先出队列，进行payload重组，更新后再入队列
			flow.list.Remove(flow.list.Back())
			upAssembInfo(flows, payload)
			pi := newStack(flows.assembPay, curDir)
			flow.list.PushBack(pi)
		}
	} else {
		flow := newFlow(key, proto, dp)
		pi := newStack(payload, FlowDirUp)
		flow.list.PushBack(pi)

		//记录临时重组信息
		setAssembInfo(flows, FlowDirUp, payload)
		appendFlows(flows, flow, key)
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
