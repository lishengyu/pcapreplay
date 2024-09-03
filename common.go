package pcapreplay

import (
	"container/list"
	"crypto/md5"
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
	"go.uber.org/zap"
)

type Stack struct {
	payload   []byte
	len       int
	dir       int
	expectlen int
	pktSeq    int
	fake      bool
}

type FlowInfo struct {
	tuple     string
	proto     string
	dp        string
	assembLen int
	assembDir int
	pktDirSeq [FlowDirMax]int
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
	FlowDirMax
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
		FlowDirUp:   "上行",
		FlowDirDn:   "下行",
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

func newStack(payload []byte, dir int, expect int, seq [FlowDirMax]int) Stack {
	pay := Stack{
		payload:   payload,
		len:       len(payload),
		dir:       dir,
		expectlen: expect,
		pktSeq:    seq[dir],
	}
	return pay
}

func newTailStack(len int, dir int) Stack {
	if dir == FlowDirUp {
		pay := Stack{
			expectlen: len,
			dir:       FlowDirDn,
			fake:      true,
		}
		return pay
	} else {
		pay := Stack{
			expectlen: len,
			dir:       FlowDirUp,
			fake:      true,
		}
		return pay
	}
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

func updateAssembInfo(flow *FlowInfo, dir, len int) {
	if flow.assembDir == dir {
		flow.assembLen += len
	} else {
		flow.assembDir = dir
		flow.assembLen = len
	}
}

func updatePktCount(flow *FlowInfo, dir int) {
	flow.pktDirSeq[dir] += 1
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

func printFlowsInfo(zlog *zap.Logger, path string, flows *Flows) {
	for _, flow := range flows.flow {
		zlog.Info("加载报文", zap.String("pcap", path), zap.String("tuple", flow.tuple), zap.String("proto", flow.proto), zap.Int("pkts", flow.list.Len()))
		var index int
		for e := flow.list.Front(); e != nil; e = e.Next() {
			value := e.Value.(Stack)
			index++
			zlog.Info("加载报文", zap.String("pcap", path), zap.Int("索引", index), zap.String("方向", FlowDirDesc[value.dir]), zap.Int("序号", value.pktSeq),
				zap.Int("总数", flow.pktDirSeq[value.dir]), zap.Int("发送长度", value.len), zap.Int("接收长度", value.expectlen))
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

func AddFlowExtraNode(flow *FlowInfo, dir int, payload []byte) {
	pi := newStack(payload, dir, 0, flow.pktDirSeq)
	flow.list.PushBack(pi)
}

func AddFlowNode(flow *FlowInfo, dir int, payload []byte) {
	var expectLen int
	if flow.assembDir != dir {
		expectLen = flow.assembLen
	} else {
		expectLen = 0
	}

	pi := newStack(payload, dir, expectLen, flow.pktDirSeq)
	flow.list.PushBack(pi)

	//更细报文统计信息
	updatePktCount(flow, dir)

	//记录临时重组信息
	updateAssembInfo(flow, dir, len(payload))
}

func AddFlowTailNode(flows *Flows) {
	for _, flow := range flows.flow {
		//添加最后的伪节点
		tail := newTailStack(flow.assembLen, flow.assembDir)
		flow.list.PushBack(tail)
		//重置assemble
		flow.assembDir = FlowDirNone
		flow.assembLen = 0
	}
}

func updateFlowPayload(flows *Flows, packet gopacket.Packet, firstPay []byte) {
	L3 := getNetworkLayer(packet)
	L4 := getTransportLayer(packet)
	payload := getPayloadInfo(packet)

	if L3 == nil || L4 == nil || len(payload) == 0 {
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
		AddFlowNode(flow, curDir, payload)
	} else {
		flow := newFlow(key, proto, dp)
		//----------------------------------
		//终端信息节点
		AddFlowExtraNode(flow, FlowDirUp, firstPay)
		//----------------------------------
		//报文内容节点
		AddFlowNode(flow, FlowDirUp, payload)
		//追加流
		appendFlows(flows, flow, key)
	}
}

func LoadPcapPayloadFile(zlog *zap.Logger, path string, uuid string) (*FlowInfo, error) {
	if exist := pathExists(path); !exist {
		return nil, fmt.Errorf(fmt.Sprintf("File [%s] Not exist!\n", path))
	}

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	flows := NewFlows()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		updateFlowPayload(flows, packet, []byte(uuid))
	}

	AddFlowTailNode(flows)
	printFlowsInfo(zlog, path, flows)

	if len(flows.flow) == 0 {
		return nil, fmt.Errorf("新建流条目数为0")
	}

	zlog.Info("只取第一条流进行回放")
	return flows.flow[0], nil
}
