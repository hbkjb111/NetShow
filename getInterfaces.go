package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	str:=""

	// Print device information
	for _, d := range devices {
		str=str+"\nName: "+ d.Name+"\r\n"
		str=str+"Description: "+d.Description+"\r\n"
		str=str+"Devices addresses: "+ d.Description

		for _, address := range d.Addresses {
			str=str + "- IP address: "+ address.IP.String() +"\r\n"

		}
	}
	fmt.Println(str)
	err= ioutil.WriteFile("net_interface.tmp", []byte(str), 0666)
	if err != nil {
		log.Fatal(err)
	}

}