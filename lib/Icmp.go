package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)
//-----------------------
//ServerScan的ICMP探测模块;
//-----------------------
var (
	icmp ICMP
	AliveHosts []string
)
type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
}

func isping(ip string) bool {
	icmp.Type = 8
	icmp.Code = 0
	icmp.Checksum = 0
	icmp.Identifier = 0
	icmp.SequenceNum = 0
	recvBuf := make([]byte, 32)
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, icmp)
	icmp.Checksum = checkSum(buffer.Bytes())
	buffer.Reset()
	binary.Write(&buffer, binary.BigEndian, icmp)
	Time, _ := time.ParseDuration("2s")
	conn, err := net.DialTimeout("ip4:icmp", ip, Time)
	if err != nil {
		return false
	}
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	num, err := conn.Read(recvBuf)
	if err != nil {
		return false
	}
	conn.SetReadDeadline(time.Time{})
	if string(recvBuf[0:num]) != "" {
		return true
	}
	return false

}

func checkSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)
	return uint16(^sum)
}

func icmpCheck(hostslist []string) {
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	for _,host :=range hostslist{
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if isping(host){
				mutex.Lock()
				AliveHosts = append(AliveHosts, host)
				mutex.Unlock()
			}
		}(host)
	}
	wg.Wait()
}

func execCommandPing(ip string,bsenv string) bool {
	command := exec.Command(bsenv, "-c", "ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false")
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil{
		return false
	}

	if err = command.Wait();err!=nil{
		return false
	}else{
		if(strings.Contains(outinfo.String(), "true")) {
			return true
		}else {
			return false
		}
	}
}

func pingCMDcheck(hostslist []string,bsenv string) {
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, 40)
	aliveHost := make(chan string, 20)
	go func() {
		for s := range aliveHost {
			fmt.Println(s)
		}
	}()
	for _,host :=range hostslist{
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()
			if execCommandPing(host,bsenv){
				mutex.Lock()
				AliveHosts = append(AliveHosts, host)
				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
	close(aliveHost)
}

//探测启动函数
func ICMPRun(hostslist []string)  []string{
	var sysinfo SystemInfo
	sysinfo = GetSys()
	if sysinfo.OS == "windows" {
		icmpCheck(hostslist)
	}else if sysinfo.OS == "linux" {
		if sysinfo.Groupid == "0" || sysinfo.Userid == "0" || sysinfo.Username == "root" {
			icmpCheck(hostslist)
		}else {
			pingCMDcheck(hostslist,"/bin/bash")
		}
	}else if sysinfo.OS == "darwin" {
		if sysinfo.Groupid == "0" || sysinfo.Userid == "0" || sysinfo.Username == "root" {
			icmpCheck(hostslist)
		}else {
			pingCMDcheck(hostslist,"/usr/local/bin/bash")
		}
	}
	return AliveHosts
}