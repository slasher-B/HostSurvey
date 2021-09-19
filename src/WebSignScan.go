package src

import (
	"fmt"
	"mods/lib"
	"strconv"
	"sync"
)
//---------------------------------
//dismap的核心代码,仅识别web服务的指纹;
//对比源文件优化了代码结构;
//@author: B
//---------------------------------
//指纹识别模块
//@param: hostList=目标ip列表
//@param: port=要检测的端口
func WebSignRun(domainList []string,port string,timeout int, proxy string) []string{
	var resList []string
	rch := make(chan string,1024)
	portList := lib.ParsePort(port)
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	fmt.Println("[INFO]开始WEB指纹识别...")
	IntSyncUrl := 0
	IntAllUrl := 0
	IntIdeUrl := 0
	// 线程控制
	g := 20
	if len(domainList)>5 && len(domainList)<=50 {
		g = 40
	}else if len(domainList)>50 && len(domainList)<=100 {
		g = 50
	}else if len(domainList)>100 && len(domainList)<=150 {
		g = 60
	}else if len(domainList)>150 && len(domainList)<=200 {
		g = 70
	}else if len(domainList)>200 {
		g = 75
	}
	for _, h := range domainList {
		for _, p := range portList {
			wg.Add(1)
			IntSyncUrl++
			url := lib.ParseUrl(h, strconv.Itoa(p))
			go func(url string) {
				var(
					res_code      string
					res_result    string
					res_result_nc string
					res_url       string
					res_title     string
				)
				for _, results := range lib.Identify(url, timeout, proxy) {
					res_code = results.RespCode
					res_result = results.Result
					res_result_nc = results.ResultNc
					res_url = results.Url
					res_title = results.Title
				}
				lock.Lock()
				if len(res_result) != 0 {
					IntIdeUrl++
					IntAllUrl++
					fmt.Println("[+]<"+res_code+">"+ res_url + " -> " + res_result_nc + " 页面标题:("+res_title+")")
					rch <- res_url + "," + res_result_nc
				} else if res_code != "" {
					IntAllUrl++
					fmt.Printf("[-]<%s>%s -> 页面标题:(%s)\n",res_code,res_url,res_title)
				}
				lock.Unlock()
				wg.Done()
			}(url)
			if IntSyncUrl >= g {
				IntSyncUrl = 0
				wg.Wait()
			}
		}
	}
	wg.Wait()
	close(rch)
	for {
		res := <-rch
		if res == ""{break}
		resList = append(resList, res)
	}
	fmt.Println("[INFO]指纹识别完成")
	return resList
}
