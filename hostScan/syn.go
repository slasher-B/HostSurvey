package hostScan

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"sync"
	"time"
)
//---------------------------------------
//主机发现模块,syn扫描,请求80端口;
//RST/SYN-ACK=存活,其他结果=主机关闭或不存在;
//@author: B
//---------------------------------------

//gopacket抓包
func ListenSA(ctx context.Context) {
	// 开启实时捕捉数据包
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	defer handle.Close()
	// 设置过滤规则,BPF语法
	handle.SetBPFFilter("ip.dst " + ipNet.String() + " && tcp")
	// 创建数据包源
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():// 读取数据包
			tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)// 数据处理
			if tcp.ACK{
				ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				pushData(ip.SrcIP.String(),nil,"","")
			}
		}
	}
}

// gopacket构造并发送syn包
// @param:ip=目标IP地址
func SendSynPackage(ip IP,wg *sync.WaitGroup) {
	defer wg.Done()
	srcIp := net.ParseIP(ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip解析出错")
	}
	// 以太网首部,IP/TCP
	ether := &layers.Ethernet{
		SrcMAC: localHaddr,
		DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	a := &layers.TCP{
		BaseLayer:  layers.BaseLayer{},
		SrcPort:    0,
		DstPort:    80,
		Seq:        0,
		Ack:        0,
		DataOffset: 0,
		FIN:        false,
		SYN:        true,
		RST:        false,
		PSH:        false,
		ACK:        false,
		URG:        false,
		ECE:        false,
		CWR:        false,
		NS:         false,
		Window:     0,
		Checksum:   0,
		Urgent:     0,
		Options:    nil,
		Padding:    nil,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()
	// 发送数据包
	handle, err := pcap.OpenLive(iface, 2048, false, 30 * time.Second)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("syn数据包发送失败..")
	}
}

func sendSYN(ips []string) {
	var wg sync.WaitGroup
	c := 0
	for _, ip := range ips {
		ip := ParseIPString(ip)
		if c == 100{
			wg.Wait()
			continue
		}
		wg.Add(1)
		c++
		go SendSynPackage(ip,&wg)
	}
}

func returnData() []string{
	var resList []string
	for ip := range data {
		resList = append(resList, ip)
	}
	return resList
}

func RunSYN(iface string,tarList []string) []string{
	var resList []string
	// 初始化data、网络信息
	data = make(map[string]Info)
	do = make(chan string)
	setupNetInfo(iface)

	ctx, cancel := context.WithCancel(context.Background())
	go ListenSA(ctx)
	go sendSYN(tarList)
	// 4秒抓一次包
	t = time.NewTicker(4 * time.Second)
	for {
		select {
		case <-t.C:
			resList = returnData()
			cancel()
			goto END
		case d := <-do:
			switch d {
			case START:
				t.Stop()
			case END:
				// 接收到新数据，重置2秒的计数器
				t = time.NewTicker(2 * time.Second)
			}
		}
	}
END:
	return resList
}
