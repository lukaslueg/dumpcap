// Capture traffic from loopback interface for some time and dissect the
// captured packets using gopacket
package main

import (
	"fmt"
	"log"

	"github.com/lukaslueg/dumpcap"

	"code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
)

func openFile(fname string) (handle *pcap.Handle, packetSource *gopacket.PacketSource, err error) {
	if handle, err = pcap.OpenOffline(fname); err != nil {
		return nil, nil, err
	}
	return handle, gopacket.NewPacketSource(handle, handle.LinkType()), nil
}

func handlePackets(packetSource *gopacket.PacketSource, packetCount uint64) error {
	var i uint64
	for i = 0; i < packetCount; i++ {
		packet, err := packetSource.NextPacket()
		if err != nil {
			return err
		}
		log.Println(packet.String())
	}
	return nil
}

func main() {
	fmt.Println(dumpcap.VersionString())

	// Setup dumpcap to capture on loopback for ten seconds, switching between
	// files every three seconds.
	args := dumpcap.Arguments{
		DeviceArgs:       []dumpcap.DeviceArgument{{Name: "lo"}},
		FileFormat:       dumpcap.UsePCAP,
		FileName:         "/tmp/foobar",
		SwitchOnDuration: 3,
		StopOnDuration:   10}

	c, err := dumpcap.NewCapture(args)
	if err != nil {
		panic(err)
	}

	var packetSource *gopacket.PacketSource
	var handle *pcap.Handle

	for msg := range c.Messages {
		switch msg.Type {
		case dumpcap.FileMsg:
			// Dumpcap has started writing packets to a new file and (since we
			// are synchronous) all previous packets were processed. Close the
			// handle to the current file (we could also unlink it) and open
			// the new one.
			if handle != nil {
				handle.Close()
			}
			handle, packetSource, err = openFile(msg.Text)
			if err != nil {
				panic(err)
			}
			log.Println("Now working on", msg.Text)
		case dumpcap.PacketCountMsg:
			// Dumpcap has written the reported amount of packets to the
			// current file. We can process that many packets without hitting
			// EOF.
			if err = handlePackets(packetSource, msg.PacketCount); err != nil {
				panic(err)
			}
		case dumpcap.ErrMsg, dumpcap.BadFilterMsg:
			panic(msg.Text)
		}
	}

	if err = c.Wait(); err != nil {
		log.Fatal(err)
	} else {
		log.Println("Dumpcap has exited normally")
	}
}
