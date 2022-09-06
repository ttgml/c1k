package client

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

//速率控制 控制建立连接的速率
func RateControl(wg *sync.WaitGroup) {
	//根据发包间隔时间控制发包速度
	var sleepInterval int32 = 1000 * 1000 * 1000 / C_rate
	basePi, sips, port_start, port_end, err := ParseSynBaseInfo()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var reqCount = 0
	var next = true
	for _, sip := range sips {
		if !next {
			break
		}
		for i := port_start; i < port_end; i++ {
			if reqCount == C_count {
				next = false
			}
			if !next {
				break
			}
			time.Sleep(time.Duration(sleepInterval) * time.Nanosecond)
			basePi.SIp = sip
			basePi.SPort = layers.TCPPort(uint16(i))
			Pi_channel <- basePi
			reqCount++
		}
	}

	time.Sleep(2 * time.Second)
	wg.Done()
}
