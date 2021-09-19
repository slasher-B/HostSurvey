package src

import (
	"fmt"
	"mods/lib"
	"net"
	"strconv"
	"sync"
	"time"
)
//----------------------------------------------
//ServerScan端口扫描的核心代码, 扫描原理: 全连接扫描;
//@author: B
//----------------------------------------------
//全连接扫描,直接发送请求到 ip:port,
//有回应=主机存活+端口开放;
func ProbeHosts(host string, ports <-chan int, respondingHosts chan<- string, done chan<- bool, adjustedTimeout int) {
	Timeout := time.Duration(adjustedTimeout) * time.Second
	for port := range ports{
		start := time.Now()
		con, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), Timeout)
		duration := time.Now().Sub(start)
		if err == nil {
			defer con.Close()
			address := host + ":" + strconv.Itoa(port)
			fmt.Printf("[TCP] 目标 %s 端口开放\n",address)
			respondingHosts <- address
		}
		if duration < Timeout {
			difference := Timeout - duration
			Timeout = Timeout - (difference / 2)
		}
	}
	done <- true
}

//执行扫描,结果处理
func ScanAllports(address string, probePorts []int, threads int, timeout time.Duration, adjustedTimeout int) ([]string, error) {
	ports := make(chan int, 20)
	results := make(chan string, 10)
	done := make(chan bool, threads)

	for worker := 0; worker < threads; worker++ {
		go ProbeHosts(address, ports, results, done, adjustedTimeout)
	}
	for _,port := range probePorts{
		ports <- port
	}
	close(ports)
	var responses []string
	for {
		select {
		case found := <-results:
			responses = append(responses, found)
		case <-done:
			threads--
			if threads == 0 {
				return responses, nil
			}
		case <-time.After(timeout):
			return responses, nil
		}
	}
}

//线程启动方法
func TCPportScan(hostslist []string,ports string,timeout int)  ([]string,[]string){
	var AliveAddress []string
	var aliveHosts []string
	probePorts := lib.ParsePort(ports)
	lm := 20
	if len(hostslist)>5 && len(hostslist)<=50 {
		lm = 40
	}else if len(hostslist)>50 && len(hostslist)<=100 {
		lm = 50
	}else if len(hostslist)>100 && len(hostslist)<=150 {
		lm = 60
	}else if len(hostslist)>150 && len(hostslist)<=200 {
		lm = 70
	}else if len(hostslist)>200 {
		lm = 75
	}
	thread := 5
	if len(probePorts)>500 && len(probePorts)<=4000 {
		thread = len(probePorts)/100
	}else if len(probePorts)>4000 && len(probePorts)<=6000 {
		thread = len(probePorts)/200
	}else if len(probePorts)>6000 && len(probePorts)<=10000 {
		thread = len(probePorts)/350
	}else if len(probePorts)>10000 && len(probePorts)<50000 {
		thread = len(probePorts)/400
	}else if len(probePorts)>=50000 && len(probePorts)<=65535 {
		thread = len(probePorts)/500
	}

	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, lm)
	aliveHost := make(chan string, lm/2)
	fmt.Println("[INFO]扫描模块开启...")
	for _,host :=range hostslist{
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer wg.Done()
			if aliveAdd, err := ScanAllports(host, probePorts,thread, 5*time.Second,timeout);err == nil && len(aliveAdd)>0{
				mutex.Lock()
				aliveHosts = append(aliveHosts,host)
				for _,addr :=range aliveAdd{
					AliveAddress = append(AliveAddress,addr)
				}
				mutex.Unlock()
			}
			<-limiter
		}(host)
	}
	wg.Wait()
	close(aliveHost)
	fmt.Println("[INFO]扫描完成")
	return aliveHosts,AliveAddress
}