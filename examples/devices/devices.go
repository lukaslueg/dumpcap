// Report all available devices and some of their capabilities to stdout
package main

import (
	"fmt"

	"github.com/lukaslueg/dumpcap"
)

func main() {
	fmt.Println(dumpcap.VersionString())

	devices, err := dumpcap.Devices(true)
	if err != nil {
		panic(err)
	}

	fmt.Println("No.\tName\tWifi?\tLinkLayer")
	var isWifi string
	for _, dev := range devices {
		if dev.CanRFMon {
			isWifi = "Yes"
		} else {
			isWifi = "No"
		}
		fmt.Printf("%d\t%s\t%s\t%s\n", dev.Number, dev.Name, isWifi, dev.LLTs[0].Name)
	}
}
