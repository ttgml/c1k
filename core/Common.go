package core

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type packet struct {
	bytes   []byte
	smac    net.HardwareAddr
	dmac    net.HardwareAddr
	sip     net.IP
	dip     net.IP
	sport   layers.TCPPort
	dport   layers.TCPPort
	synFlag bool
	ackFlag bool
	rst     bool
	date    []byte
	seq     uint32
	ack     uint32
}

func (p *packet) Parse() (*packet, error) {
	if p.bytes == nil {
		return nil, errors.New("packet parse fail: nil bytes")
	}
	//TODO : parse byte array data to struct

	return p, nil
}

func (p *packet) setMac(smac net.HardwareAddr, dmac net.HardwareAddr) *packet {
	p.smac = smac
	p.dmac = dmac
	return p
}
func (p *packet) setIp(sip net.IP, dip net.IP) *packet {
	p.sip = sip
	p.dip = dip
	return p
}
func (p *packet) setPort(sport layers.TCPPort, dport layers.TCPPort) *packet {
	p.sport = sport
	p.dport = dport
	return p
}
func (p *packet) isFirstPacket() *packet {
	p.synFlag = true
	p.ackFlag = false
	return p
}

func (p *packet) build_bytes() (gopacket.SerializeBuffer, error) {
	if p.smac == nil {
		return nil, errors.New("packet need init")
	}
	eth := layers.Ethernet{
		SrcMAC:       p.smac,
		DstMAC:       p.dmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    p.sip,
		DstIP:    p.dip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: p.sport,
		DstPort: p.dport,
		ACK:     p.ackFlag,
		SYN:     p.synFlag,
		Window:  65280,
		Seq:     10000,
	}
	err := tcpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		panic(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &ipLayer, &tcpLayer)
	if err != nil {
		panic(err)
	}
	return buf, nil
}
