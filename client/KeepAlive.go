package client

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

func KeepAlive() {
	var sleepInterval int32 = 1000 * 1000 * 1000 / C_rate
	fmt.Println(sleepInterval)
	var push_interval int32 = 20
	handle, err := pcap.OpenLive(C_interface, 1600, true, pcap.BlockForever)
	fmt.Println("parseSynBaseInfo().start")
	basePi, _, _, _, err := ParseSynBaseInfo()
	fmt.Println("parseSynBaseInfo().done")
	if err != nil {
		panic(err)
	}
	for {
		time.Sleep(time.Duration(push_interval) * time.Second)
		//for key, value := range mapPshList {
		//    buf := BuildPshPacket(key,value,basePi)
		//    handle.WritePacketData(buf.Bytes())
		//    fmt.Println("send a push packet: ",key,value,basePi)
		//    if err != nil {
		//        fmt.Println("send packet error")
		//    }
		//    time.Sleep(time.Duration(sleepInterval)*time.Nanosecond)
		//}
		var op = 0
		mapPshListSync.Range(func(key, value interface{}) bool {
			op++
			fmt.Println("op: ", op)
			buf := BuildPshPacket(key.(PshKey), value.(PshValue), basePi)
			handle.WritePacketData(buf.Bytes())
			fmt.Println("send a push packet: ", key, value, basePi)
			if err != nil {
				fmt.Println("send packet error")
			}
			time.Sleep(time.Duration(sleepInterval) * time.Nanosecond)
			return true
		})
	}
	wg.Done()
}

func BuildPshPacket(key PshKey, value PshValue, baseP Pinfo) gopacket.SerializeBuffer {
	//缺少逻辑
	eth := layers.Ethernet{
		SrcMAC:       baseP.SMac,
		DstMAC:       baseP.DMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    net.ParseIP(key.Ip),
		DstIP:    baseP.DIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(key.Port),
		DstPort: baseP.DPort,
		ACK:     true,
		SYN:     false,
		Window:  65280,
		Seq:     value.Seq,
		Ack:     value.Ack,
		PSH:     true,
	}
	data := []byte(`ln`) // 应用数据
	payload := gopacket.Payload(data)
	err := tcpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		panic(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &ipLayer, &tcpLayer, payload)
	if err != nil {
		panic(err)
	}
	return buf
}
