// Receive statistics about traffic seen on all devices from dumpcap. Dumpcap
// is gracefully closed automatically after five seconds (otherwise it would
// run forever).
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/lukaslueg/dumpcap"
)

func main() {
	fmt.Println(dumpcap.VersionString())

	stats, err := dumpcap.NewStatistics()
	if err != nil {
		panic(err)
	}

	go func() {
		<-time.After(5 * time.Second)
		stats.Close()
	}()

	for {
		ds, ok := <-stats.Stats
		if !ok {
			log.Println("Receiver has stopped")
			break
		}
		log.Println(ds)
	}
	if err = stats.Wait(); err != nil {
		log.Println(err)
	} else {
		log.Println("Dumpcap exited normally")
	}

}
