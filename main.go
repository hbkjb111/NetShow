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
	"regexp"
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



//device
var (
	// device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)


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


func makeMess(stream_mess  streamMess) streamMess {
	stream_mess.HostIn.All=stream_mess.HostIn.Local+stream_mess.HostIn.External
	stream_mess.HostOut.All=stream_mess.HostOut.Local+stream_mess.HostOut.External
	stream_mess.Host.Local=stream_mess.HostOut.Local+stream_mess.HostIn.Local
	stream_mess.Host.External=stream_mess.HostOut.External+stream_mess.HostIn.External
	stream_mess.Host.All=stream_mess.Host.Local+stream_mess.Host.External
	stream_mess.Time=time.Now().Format("2006-01-02 15:04:05")
	return stream_mess
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


func streamSend(stream_mess *streamMess,conn  net.Conn){
	stream:=makeMess(*stream_mess)
	stream_json, _ := json.Marshal(stream)
	_, err := conn.Write([]byte(stream_json))
	if err != nil {
		log.Println("[ERROR] ", err)

	}

}

func streamSave(stream_mess *streamMess,file string){

	stream:=makeMess(*stream_mess)
	stream_json, _ := json.Marshal(stream)
	err := ioutil.WriteFile(file, stream_json, 0666)
	if err != nil {
		log.Fatal(err)
	}

}



func streamGet(stream_mess *streamMess ,dev string) {


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
	var filter string = "tcp and udp"
	handle.SetBPFFilter(filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		if packet.ApplicationLayer() == nil  {
			continue
		}
		fmt.Println(len(packet.Data()))
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
					if getIPrange(hostip)==getIPrange(key_ip) {
						stream_mess.HostOut.Local=allLen

					//external
					}else {
						stream_mess.HostOut.External=allLen
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
					if getIPrange(hostip)==getIPrange(key_ip) {
						stream_mess.HostIn.Local=allLen

					//external
					}else {
						stream_mess.HostIn.External=allLen
					}

				}
		}
		//-----------------------------------------------------------------------------------
		//	fmt.Println(packet.Metadata().Timestamp.Unix())
		//	fmt.Println(packet.Metadata().Length)
		//	fmt.Println(packet.Metadata().CaptureLength)
		//-----------------------------------------------------------------------------------
		//	printPacketInfo(packet)
	}

}






func main(){
	file:="./stream.tmp"
	dev :="\\Device\\NPF_{6C139085-9D00-4A06-8658-FB9448DFBB9C}"
	stream_mess,ok :=streamInit(file)
	if ok{
		// write file
		go func() {
			for {
				streamSave(&stream_mess, file)
				time.Sleep(1*time.Minute)
			}
		}()

		//go  streamSend(&stream_mess)
		streamGet(&stream_mess,dev)

	}else {
		var stream_mess streamMess
		detail_dict:=make(map[string]*detail)
		stream_mess.Detail=detail_dict
		// write file
		go func() {
			for {
				streamSave(&stream_mess, file)
				time.Sleep(1*time.Minute)
			}
		}()
		//go  streamSend(&stream_mess)
		streamGet(&stream_mess,dev)


	}








}
