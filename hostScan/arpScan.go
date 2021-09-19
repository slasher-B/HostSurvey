package hostScan

import (
	"context"
	"github.com/sirupsen/logrus"
	manuf "github.com/timest/gomanuf"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

//---------------------------------------
//主机发现模块,为内网定制的arp扫描;
//整合来自<goscan>,优化了代码结构,做成一个模块;
//@author: B
//---------------------------------------

var (
	log =      logrus.New()
	ipNet      *net.IPNet        // 存放IP地址
	localHaddr net.HardwareAddr  // 存放子网掩码
	iface      string            // 本机的mac地址
	data       map[string]Info // 存放最终的数据，key[string] 存放的是IP地址
	t          *time.Ticker    // 计时器，在一段时间没有新的数据写入data中，退出程序，反之重置
	do         chan string
)
const (// 3秒的计时器
	START = "start"
	END   = "end"
)
type Info struct {
	Mac      net.HardwareAddr  // IP地址
	Hostname string            // 主机名
	Manuf    string            // 厂商信息
}
func localHost() {
	host, _ := os.Hostname()
	data[ipNet.IP.String()] = Info{Mac: localHaddr, Hostname: strings.TrimSuffix(host, ".local"), Manuf: manuf.Search(localHaddr.String())}
}

// 格式化输出结果
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
func PrintData() {
	var keys IPSlice
	for k := range data {
		keys = append(keys, ParseIPString(k))
	}
	sort.Sort(keys)
	for _, k := range keys {
		d := data[k.String()]
		mac := ""
		if d.Mac != nil {
			mac = d.Mac.String()
		}
		log.Infof("%-15s %-17s %-30s %-10s\n", k.String(), mac, d.Hostname, d.Manuf)
	}
}

// 结果处理函数
// 将抓到的数据集加入到data中，同时重置计时器
func pushData(ip string, mac net.HardwareAddr, hostname, manuf string) {
	// 停止计时器
	do <- START
	var mu sync.RWMutex
	mu.RLock()
	defer func() {
		// 重置计时器
		do <- END
		mu.RUnlock()
	}()
	if _, ok := data[ip]; !ok {
		data[ip] = Info{Mac: mac, Hostname: hostname, Manuf: manuf}
		return
	}
	info := data[ip]
	if len(hostname) > 0 && len(info.Hostname) == 0 {
		info.Hostname = hostname
	}
	if len(manuf) > 0 && len(info.Manuf) == 0 {
		info.Manuf = manuf
	}
	if mac != nil {
		info.Mac = mac
	}
	data[ip] = info
}

// 初始化网络信息
func setupNetInfo(f string) {
	var ifs []net.Interface
	var err error
	if f == "" {
		ifs, err = net.Interfaces()
	} else {
		// 已经选择iface
		var it *net.Interface
		it, err = net.InterfaceByName(f)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Fatal("无法获取本地网络信息:", err)
	}
	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					ipNet = ip
					localHaddr = it.HardwareAddr
					f = it.Name
					goto END
				}
			}
		}
	}
	END:
		if ipNet == nil || len(localHaddr) == 0 {
			log.Fatal("无法获取本地网络信息")
		}
}

func sendARP() {
	ips := Table(ipNet)
	var wg sync.WaitGroup
	c := 0
	for _, ip := range ips {
		if c == 100{
			wg.Wait()
			continue
		}
		wg.Add(1)
		c++
		go SendArpPackage(ip,&wg)
	}
}

//启动扫描
func ArpScanRun(iface string) []string{
	var resList []string
	// 初始化data、网络信息
	data = make(map[string]Info)
	do = make(chan string)
	setupNetInfo(iface)

	ctx, cancel := context.WithCancel(context.Background())
	go ListenARP(ctx)
	go ListenMDNS(ctx)
	go ListenNBNS(ctx)
	go sendARP()
	go localHost()

	t = time.NewTicker(4 * time.Second)
	for {
		select {
		case <-t.C:
			PrintData()
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


