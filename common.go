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
	payload   []byte
	len       int
	dir       int
	expectlen int
	fake      bool
}

type FlowInfo struct {
	tuple     string
	proto     string
	dp        string
	assembLen int
	assembDir int
	list      *list.List
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
		tuple:     key,
		proto:     proto,
		dp:        dp,
		assembLen: 0,
		assembDir: FlowDirUp,
		list:      list.New(),
	}
	return flow
}

func newStack(payload []byte, dir int, expect int) Stack {
	pay := Stack{
		payload:   payload,
		len:       len(payload),
		dir:       dir,
		expectlen: expect,
	}
	return pay
}

func newTailStack(len int) Stack {
	pay := Stack{
		expectlen: len,
		fake:      true,
	}
	return pay
}

func updateTailStack(st *Stack, len int) {
	st.expectlen = len
}

func updateStack(st *Stack, payload []byte, dir int, expect int) {
	st.payload = payload
	st.len = len(payload)
	st.dir = dir
	st.expectlen = expect
}

func appendFlows(flows *Flows, flow *FlowInfo, key string) {
	flows.flow = append(flows.flow, flow)
	flows.exist[key] = flows.num
	flows.num++
}

// 重置重组信息
func setAssembInfo(flow *FlowInfo, dir, len int) {
	flow.assembDir = dir
	flow.assembLen = len
}

// 更新重组信息
func upAssembInfo(flow *FlowInfo, len int) {
	flow.assembLen += len
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
			log.Printf("负载和上下行关系：[%d][%d|%d]:[%s]\n", index, value.len, value.expectlen, FlowDirDesc[value.dir])
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
		if flow.assembDir != curDir { //上下行切换，入队列
			//伪节点出队
			flow.list.Remove(flow.list.Back())

			//只有状态切换的情况下，才需要保存预期的接收字节长度
			//但是最后一个方向的状态，没有切换无法保存，需要追加一个节点
			pi := newStack(payload, curDir, flow.assembLen)
			flow.list.PushBack(pi)

			//更新重组信息
			setAssembInfo(flow, curDir, len(payload))

			//伪节点入队
			tail := newTailStack(flow.assembLen)
			flow.list.PushBack(tail)
		} else {
			//伪节点出队
			flow.list.Remove(flow.list.Back())
			//同方向，直接入队
			pi := newStack(payload, curDir, 0)
			flow.list.PushBack(pi)

			//更新重组信息
			upAssembInfo(flow, len(payload))

			//伪节点入队
			tail := newTailStack(flow.assembLen)
			flow.list.PushBack(tail)
		}
	} else {
		flow := newFlow(key, proto, dp)
		pi := newStack(payload, FlowDirUp, 0)
		flow.list.PushBack(pi)

		//记录临时重组信息
		setAssembInfo(flow, FlowDirUp, len(payload))
		//添加最后的伪节点
		tail := newTailStack(flow.assembLen)
		flow.list.PushBack(tail)

		//追加流
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
