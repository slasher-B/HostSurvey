package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"mods/config"
	"mods/hostScan"
	"mods/lib"
	"mods/src"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)
//------------------------------------------------------------------------------
//这是一个go编写的，有主机发现、端口扫描、服务识别功能的命令行工具,可适应内外网,设计模型参考nmap,
//原本是准备用来加进SutureMonster这个项目的，结果发现可以独立出来当一个小工具,
//于是就有了HostSurvey,这个项目整合并魔改了goscan、serverscan_pro和dismap,
//优化了代码结构和输出方式,加入代理支持;
//@author: B
//------------------------------------------------------------------------------
var(
	TARGET  string
	FILE    string
	PORT    string
	OUTPUT  string
	MOD     string
	PROXY   string
	NETWORK string
	TIMEOUT int
	PING    bool
	FLAG    bool

	ipList    []string
	result    []string
)
func init() {
	fmt.Println("    __  __           __  _____                            \n" +
		"   / / / /___  _____/ /_/ ___/__  ________   _____  __  __\n" +
		"  / /_/ / __ \\/ ___/ __/\\__ \\/ / / / ___/ | / / _ \\/ / / /\n" +
		" / __  / /_/ (__  ) /_ ___/ / /_/ / /   | |/ /  __/ /_/ / \n" +
		"/_/ /_/\\____/____/\\__//____/\\__,_/_/    |___/\\___/\\__, /  \n" +
		"                                                 /____/   \n" +
		"                                         Author: _B_\n" +
		"-------------------------------------------------------")
	flag.StringVar(&TARGET,"addr","","[-addr 1.1.1.1 || 1.1.1.0/24 || 1.1.1.1-10 || example.com]  指定扫描ip或c段或url.")
	flag.StringVar(&FILE,"f","","[-f target.txt]  从文件读取目标,支持格式:example.org, 1.1.1.1, 1.1.1.0/24, 1.1.1.1-10")
	flag.StringVar(&PORT,"p","","[-p 21-23,25,3306,3389]  指定扫描的端口.")
	flag.StringVar(&MOD,"m","all","[-m all]  选择扫描模式:host=主机发现,port=端口扫描,sign=服务识别,all=全部.")
	flag.IntVar(&TIMEOUT,"t",5,"[-t 2]  设置等待回包的超时时间.")
	flag.StringVar(&NETWORK,"e","","[-e ethernet0]  选择host模式下用来扫描的网卡,不输入则选择默认网卡.")
	flag.StringVar(&PROXY,"proxy","","[-proxy http://127.0.0.1:10809]  设置代理,host模式下不支持.")
	flag.StringVar(&OUTPUT,"o","","[-o /opt/result.txt]  自定义输出路径.")
	flag.BoolVar(&PING,"ping",false,"[-ping]  扫描前是否对目标使用ping命令,默认不使用.")
	flag.BoolVar(&FLAG,"arp",false,"[-arp]  主机扫描模式下选择扫描模式,默认syn,可选arp.")
	flag.Parse()
}

func run(domainList map[string]string){
	if PING{
		ipList = lib.ICMPRun(ipList)
	}
	l := src.DefFormant()
	var ips      []string

	if MOD == "all"{
		fmt.Println("[INFO]HostSurvey -> 全能模式")
		var portStr  string
		var tarList  []string
		var portList []string
		if !FLAG{
			ips = hostScan.RunSYN(NETWORK,ipList)
		} else {
			ips = hostScan.ArpScanRun(NETWORK)
		}
		liveHost,liveAddr := src.TCPportScan(ips,PORT,TIMEOUT)
		// 为了兼容端口转换格式
		for _,addr := range liveAddr{
			portList = append(portList,strings.Split(addr,":")[1] + ",")
		}
		for _,port := range lib.GetOnly(portList){
			portStr += port + ","
		}
		for _,host := range liveHost{
			if domainList[host] != ""{
				tarList = append(tarList,domainList[host])
			}
		}
		signList := src.WebSignRun(tarList,portStr,TIMEOUT,PROXY)
		l.Lh = liveHost              // h.h.h.h
		l.La = liveAddr              // h.h.h.h:pp
		l.Sl = signList              // http(s)://url.com(:pp),ssss
		result = src.Formant(MOD,l)  // h.h.h.h,pp,http(s)://url.com(:pp),ssss


	} else if MOD == "host"{
		fmt.Println("[INFO]HostSurvey -> 主机探测模式")
		if lib.GetSys().OS == "windows"{
			fmt.Println("[WARN]Windows环境下需要安装winpcap -> https://www.winpcap.org/devel.htm")
		}
		if !FLAG{
			result = hostScan.RunSYN(NETWORK,ipList)
		} else {
			result = hostScan.ArpScanRun(NETWORK)
		}


	} else if MOD == "port"{
		fmt.Println("[INFO]HostSurvey -> 端口扫描模式")
		if !FLAG{
			ips = hostScan.RunSYN(NETWORK,ips)
		} else {
			ips = hostScan.ArpScanRun(NETWORK)
		}
		l.Lh,l.La = src.TCPportScan(ips,PORT,TIMEOUT)
		result = src.Formant(MOD,l)


	} else if MOD == "sign"{
		fmt.Println("[INFO]HostSurvey -> 服务识别模式")
		var domains []string
		if PROXY != ""{
			PROXY = lib.CheckProxy(PROXY)
		}
		for _,i := range ipList{
			domains = append(domains,domainList[i])
		}
		l.Sl = src.WebSignRun(domains,PORT,TIMEOUT,PROXY)
		result = src.Formant(MOD,l)
	} else {
		flag.Usage()
		return
	}
	if OUTPUT != ""{
		src.OutPutRes(result,OUTPUT)


// ----------------------- SutureMonster output begin -----------------------
		if MOD == "port"{
			var (
				portSM []string
				ipSM   []string
				path   string
			)
			for _,res := range result{
				portSM = append(portSM,strings.Split(res,",")[2])
			}
			portSM = lib.GetOnly(portSM)
			for _,p := range portSM{
				for _,r := range result{
					if p == strings.Split(r,",")[2]{
						ipSM = append(ipSM,strings.Split(r,",")[1])
					}
				}
				if lib.GetSys().OS == "windows"{
					path = filepath.Dir(OUTPUT) + "\\" + p
				} else {
					path = filepath.Dir(OUTPUT) + "/" + p
				}
				src.OutPutRes(lib.GetOnly(ipSM),path)
				ipSM = []string{}
			}
		}
// ------------------------SutureMonster output end------------------------


	}
	fmt.Println("[INFO]HostSurvey finish.")
}

func main() {
	// 参数检查
	// 1.1.1.1  1.1.1.0/32
	addrReg := regexp.
		MustCompile(`^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])/(\d{1}|[0-2]{1}\d{1}|3[0-2])$|^(25[0-5]|2[0-4]\d|1\d\d|\d{1,2})(\.(25[0-5]|2[0-4]\d|1\d\d|\d{1,2})){3}$`).
		MatchString(TARGET)
	// 1.1.1.1-10
	addrReg2 := regexp.
		MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})-((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2}))\b`).
		MatchString(TARGET)
	// example.org
	addrReg3 := regexp.
		MustCompile(`^[a-zA-Z\d][-a-zA-Z\d]{0,62}(\.[a-zA-Z\d][-a-zA-Z\d]{0,62})+$`).
		MatchString(TARGET)
	// 80  80-89  21,22
	portReg := regexp.
		MustCompile(`^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$|^\d+(-\d+)?(,\d+(-\d+)?)*$`).
		MatchString(PORT)
	// all  host  port  sign
	modReg := regexp.MustCompile(`^all$|^host$|^port$|^sign$`).MatchString(strings.ToLower(MOD))

	domainList := make(map[string]string)
	if modReg == false{
		flag.Usage()
		return
	} else if MOD == "sign" && portReg == false{
		fmt.Println("[WARN]-p参数为空或格式有误,将识别常用端口号.")
		for _,i := range config.DefaultPorts{
			PORT += strconv.Itoa(i)
		}
	} else if MOD == "host"{
		run(nil)
	}
	if TARGET != "" && FILE == "" && (addrReg == true || addrReg2 == true || addrReg3 == true){
		ips,domain := lib.ParseIP(TARGET)
		ipList = append(ipList,ips[0])
		if domain != ""{
			domainList[ips[0]] = domain
		}
	} else if TARGET == "" && FILE != ""{
		_,e := os.Stat(FILE)
		if os.IsNotExist(e){
			flag.Usage()
			return
		}
		f,_ := os.Open(FILE)
		defer f.Close()
		br := bufio.NewReader(f)
		for{
			line,_,er := br.ReadLine()
			if er == io.EOF{break}
			tmpList,domain := lib.ParseIP(string(line))
			if domain != ""{
				domainList[tmpList[0]] = domain
			}
			for _,l := range tmpList{
				ipList = append(ipList, l)
			}
		}
	}else {
		flag.Usage()
		return
	}
	run(domainList)
}