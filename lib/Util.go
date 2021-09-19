package lib

import (
	"crypto/tls"
	"fmt"
	"github.com/malfunkt/iprange"
	"mods/config"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)
//-------------
//工具类
//@author: B
//-------------

//字符串切片去重
func GetOnly(tar []string) []string{
	var res []string
	if len(res) < 1024{
		for i := range tar{
			flag := true
			for j := range res{
				if tar[i] == res[j]{
					flag = false
					break
				}
			}
			if flag{
				res = append(res,tar[i])
			}
		}
	} else {
		regMap := map[string]byte{}
		for _,e := range tar{
			l := len(regMap)
			regMap[e] = 0
			if len(regMap) != l{
				res = append(res,e)
			}
		}
	}
	return res
}

//代理检查
func CheckProxy(proxy string) string{
	pu,_ := url.Parse(proxy)
	client := &http.Client{
		Timeout: time.Duration(5) * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req,_ := http.NewRequest("GET","https://google.com",nil)
	resp,err := client.Do(req)
	if err != nil{
		fmt.Println("[WARN]指定代理失效,将跟随系统代理.")
		return ""
	} else {
		defer resp.Body.Close()
		return proxy
	}
}

//将地址拼成URL
func ParseUrl(host string, port string) string {
	var u []string
	u,e := net.LookupAddr(host)
	if e == nil{
		host = u[0]
	}
	if port == "80" {
		return "http://" + host
	} else if port == "443" {
		return  "https://" + host
	} else if len(regexp.MustCompile("443").FindAllStringIndex(port, -1)) == 1 {
		return "https://" + host + ":" + port
	} else {
		return "http://" + host + ":" + port
	}
}

//根据 c段/范围/域名 转换成ip
func ParseIP(target string) (ipList []string,domain string){
	if regexp.MustCompile(`[a-zA-Z]`).MatchString(target){
		domain = target
		if strings.HasPrefix(target,"http") {
			domain = strings.Split(target,"://")[1]
		}
		ip,_ := net.ResolveIPAddr("ip",domain)
		ipList = append(ipList, ip.String())
	}else {
		tmpList,_ := iprange.ParseList(target)
		for _,ip := range tmpList.Expand(){
			ip := ip.String()
			ipList = append(ipList, ip)
		}
	}
	return ipList,domain
}

//将传入的端口号转换成 []int
func ParsePort(portstr string) []int {
	var ports []int
	if portstr == "" {
		defport := config.DefaultPorts
		return defport
	} else {
		tmpList := strings.Split(portstr,",")
		for _,tmp := range tmpList{
			if strings.Contains(tmp,"-"){
				start,_ := strconv.Atoi(strings.Split(tmp,"-")[0])
				end,_ := strconv.Atoi(strings.Split(tmp,"-")[1])
				for port := start;port <= end;port++{
					ports = append(ports, port)
				}
			} else {
				port,_ := strconv.Atoi(tmp)
				ports = append(ports, port)
			}
		}
		return ports
	}
}

//获取系统信息
type SystemInfo struct {
	OS 			  string
	ARCH          string
	HostName      string
	Groupid  	  string
	Userid		  string
	Username	  string
	UserHomeDir	  string
}
func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	sysinfo.ARCH = runtime.GOARCH
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	}
	u, err := user.Current()
	sysinfo.Groupid = u.Gid
	sysinfo.Userid = u.Uid
	sysinfo.Username = u.Username
	sysinfo.UserHomeDir = u.HomeDir
	return sysinfo
}

//goscan
type Buffer struct {
	Data  []byte
	start int
}

func (b *Buffer) PrependBytes(n int) []byte {
	length := cap(b.Data) + n
	newData := make([]byte, length)
	copy(newData, b.Data)
	b.start = cap(b.Data)
	b.Data = newData
	return b.Data[b.start:]
}

func NewBuffer() *Buffer {
	return &Buffer{

	}
}

// 反转字符串
func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}