package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)
type pkg struct{
	All int64			`json:"all"`
	Local int64		`json:"local"`
	External  int64	`json:"external"`
}

type detail struct {
	In int64		`json:"in"`
	Out int64		`json:"out"`
}


type streamMess struct {
	Time string		`json:"time"`
	Host pkg		`json:"host"`
	HostIn  pkg		`json:"host_in"`
	HostOut pkg		`json:"host_out"`
	Detail  map[string]*detail    `json:"detail"`


}

func ipv4Find(appmess string) string {
	rep:=`([\d]+\.){3,}[\d]+`
	r, _ := regexp.Compile(rep)
	return  r.FindString(appmess)
}
func getIPrange(appmess string) string {
	rep:=`([\d]+\.){3,}`
	r, _ := regexp.Compile(rep)
	return  r.FindString(appmess)
}


func getIPlist( ip string,local_ips []string) bool{
	flag:=false
	for _,local_ip :=range  local_ips {
		if ip ==local_ip {
			flag=true
		}

	}
	return flag
}


//device
var (
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)


func setDay(date  string )  (string,bool){
	flag:=false
	day:=time.Now().Format("2006-01-02")
	if  strings.Split(date,"-")[2] !=strings.Split(day,"-")[2]{
		flag=true
	}
	return  day,flag
}


func cleanMess(stream_mess *streamMess) (streamMess) {

		stream_mess.HostIn.External=0
		stream_mess.HostIn.Local=0
		stream_mess.HostOut.External=0
		stream_mess.HostOut.Local=0
		detail_dict:=make(map[string]*detail)
		stream_mess.Detail=detail_dict

	return *stream_mess
}

func getIP(dev string) string{
	var ip string
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range devices {
		if d.Name ==dev{
			for _, address := range d.Addresses {
				ip=ipv4Find(address.IP.String())
				if ip !=""{
					break
				}
			}
			if ip!=""{
				break
			}
		}
	}
	return ip
}


func makeMess(stream_mess  *streamMess) streamMess {
	stream_mess.HostIn.All=stream_mess.HostIn.Local+stream_mess.HostIn.External
	stream_mess.HostOut.All=stream_mess.HostOut.Local+stream_mess.HostOut.External
	stream_mess.Host.Local=stream_mess.HostOut.Local+stream_mess.HostIn.Local
	stream_mess.Host.External=stream_mess.HostOut.External+stream_mess.HostIn.External
	stream_mess.Host.All=stream_mess.Host.Local+stream_mess.Host.External
	stream_mess.Time=time.Now().Format("2006-01-02 15:04:05")
	return *stream_mess
	
	
	
}

func streamInit(file string) (streamMess,bool) {
	flag:=false
	var conf streamMess
	f, err := ioutil.ReadFile(file)
	if err == nil {
		json.Unmarshal(f, &conf)
		flag=true

	}
	return  conf,flag
}


func streamSend(stream_mess streamMess,conn  net.Conn){
	stream_json, _ := json.Marshal(stream_mess)
	_, err := conn.Write([]byte(stream_json))
	if err != nil {
		log.Println("[ERROR] ", err)

	}

}

func streamSave(stream_mess streamMess,file string){
	stream_json, _ := json.Marshal(stream_mess)
	fmt.Println(string(stream_json))
	err := ioutil.WriteFile(file, stream_json, 0666)
	if err != nil {
		log.Fatal(err)
	}

}



func streamGet(stream_mess *streamMess ,dev string,local_ips []string) {


	hostip:=getIP(dev)
	if hostip ==""{
		return
	}

	// Open file instead of device
	//	handle, err = pcap.OpenOffline(pcapFile)
	handle, err = pcap.OpenLive(dev, snapshot_len, promiscuous, timeout)

	if err != nil { log.Fatal(err) }
	defer handle.Close()
	// Set filter
	var filter string = ""
	handle.SetBPFFilter(filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//for packet := range packetSource.Packets() {
	for {
		packet := <- packetSource.Packets()
		if packet.NetworkLayer() == nil  {
			continue
		}
		ipLayer  := packet.Layer(layers.LayerTypeIPv4)
		ip, ok := ipLayer.(*layers.IPv4)
		if ok {
			allLen:=int64(len(packet.Data()))

			//out
			if 	ip.SrcIP.String()==hostip {
				key_ip:=ip.DstIP.String()
				_,ok:=stream_mess.Detail[key_ip]
				if !ok {
					stream_mess.Detail[key_ip]=&detail{}
				}
				stream_mess.Detail[key_ip].Out=allLen+stream_mess.Detail[key_ip].Out
				//local
				if getIPrange(hostip)==getIPrange(key_ip) || getIPlist(key_ip,local_ips) {

					stream_mess.HostOut.Local=allLen+stream_mess.HostOut.Local

				//external
				}else {
					stream_mess.HostOut.External=allLen+stream_mess.HostOut.External
				}

			//in
			}else  if  ip.DstIP.String()==hostip{
				key_ip:=ip.SrcIP.String()
				_,ok:=stream_mess.Detail[key_ip]
				if !ok {
					stream_mess.Detail[key_ip]=&detail{}
				}
				stream_mess.Detail[key_ip].In=allLen+stream_mess.Detail[key_ip].In

				//local
				if getIPrange(hostip)==getIPrange(key_ip)|| getIPlist(key_ip,local_ips) {
					stream_mess.HostIn.Local=allLen+stream_mess.HostIn.Local

				//external
				}else {
					stream_mess.HostIn.External=allLen+stream_mess.HostIn.External
				}

			}
		}
	}

}






func main(){
	dev := os.Args[1]

	var local_ips []string

	if dev =="" {
		log.Println("[ERROR] Miss a param ......")
		return
	}
	file:="./stream.tmp"


	//dev :="\\Device\\NPF_{2E16E742-1AC5-4110-89A6-8C4FFEA78F31}"


	var stream_mess streamMess
	var ok bool
	stream_mess,_ =streamInit(file)
	if stream_mess.Detail ==nil{
		detail_dict:=make(map[string]*detail)
		stream_mess.Detail=detail_dict
	}


	// write file
	go func() {
		var stream streamMess
		date:=time.Now().Format("2006-01-02")
		for {
			date,ok=setDay(date)
			if ok {
				stream=cleanMess(&stream_mess)
			} else {
				stream=makeMess(&stream_mess)
			}
			streamSave(stream, file)
			time.Sleep(1*time.Minute)
		}
	}()

	streamGet(&stream_mess,dev,local_ips)

}

