package src

import (
	"fmt"
	"mods/lib"
	"os"
	"strings"
)

//------------
//结果输出模块
//@author: B
//------------
type formant struct {
	Lh []string
	La []string
	Sl []string
}
func DefFormant() *formant{
	return &formant{
		Lh: []string{},
		La: []string{},
		Sl: []string{},
	}
}

func Formant(mods string,sli *formant) (result []string){
	var (
		url  string
		ip   string
		port string
		sign string
		resList []string
	)
	if mods == "all"{
		for _,port_res := range sli.La{
			ip   = strings.Split(port_res,":")[0]
			for _,sign_res := range sli.Sl{
				url  = strings.Split(sign_res,",")[0]
				sign = strings.Split(sign_res,",")[1]
				domain := strings.Split(url,"://")[1]
				if strings.HasPrefix(url,"http://") && !strings.Contains(domain,":"){
					port = "80"
				} else if strings.HasPrefix(url,"https://") && !strings.Contains(domain,":"){
					port = "443"
				} else {
					port = strings.Split(domain,":")[1]
				}
				iplist,_ := lib.ParseIP(url)
				if ip == iplist[0]{
					resList = append(resList,url + "," + ip + "," + port + "," + sign)// url,ip,port,sign
				}
			}
		}
	} else if mods == "host"{
		for _,host_res := range sli.Lh{
			//get url/ip from host_res
			resList = append(resList,url + "," + host_res + ",,")// url,ip,,
		}
	} else if mods == "port"{
		for _,port_res := range sli.La{
			url = ""
			ip = strings.Split(port_res,":")[0]
			port = strings.Split(port_res,":")[1]
			resList = append(resList,url + "," + ip + "," + port + ",")// url,ip,port,
		}
	} else if mods == "sign"{
		for _,sign_res := range sli.Sl{
			url = strings.Split(sign_res,",")[0]
			domain := strings.Split(url,"://")[1]
			if strings.Contains(domain,":"){
				port = strings.Split(domain,":")[1]
			} else if !strings.Contains(domain,":") && strings.Contains(url,"http://"){
				port = "80"
			} else if !strings.Contains(domain,":") && strings.Contains(url,"https://"){
				port = "443"
			}
			sign = strings.Split(sign_res,",")[1]
			resList = append(resList,url + "," + ip + "," + port + "," + sign)// url,ip,port,sign
		}
	}
	return lib.GetOnly(resList)
}

func OutPutRes(resList []string,out string){
	f,e := os.OpenFile(out,os.O_APPEND|os.O_CREATE,0666)
	if e != nil{fmt.Printf("[ERROR]结果写入出错 -> %v",e)}
	defer f.Close()
	for _,res := range resList{
		f.WriteString(res + "\n")
	}
}
