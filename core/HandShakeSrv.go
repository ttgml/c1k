package core

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
)

// 计划单独把client的 维护连接 部分抽离出来，作为一个公共的模块，为以后的“插件”功能准备。
// 这里初始化的时候需要传一些信息给这个方法，需要在一个新的goroutine里面运行，这个模块 负责处理客户端的握手的连接信息 和 对服务端返回来的数据进行ACK操作
// 现在不确定的问题： 要不要全局只维护一个pcap句柄，这个pcap负责抓包的同事也要同步发包。
// 参考 gopacket examples / afpacket.go

const NAME = "HandShakeSrv"

var (
	snaplen    int = 8192
	bufferSize int = 8
)

func HandShakeSrv(iface string, filter string) {
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(bufferSize, snaplen, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	afpacketHandle, err := newAfpacketHandle(iface, szFrame, szBlock, numBlocks, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	//SetBPFFilter()
	afpacketHandle.SetBPFFilter(filter, snaplen)

	source := gopacket.ZeroCopyPacketDataSource(afpacketHandle.TPacket)
	defer afpacketHandle.TPacket.Close()

	bytes := uint64(0)
	packets := uint64(0)
	for {
		data, _, err := source.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}
		bytes += uint64(len(data))
		packets++
		if packets > 1000 {
			break
		}
		fmt.Println(len(data))
	}
	fmt.Println("packets: ", packets)
	fmt.Println("bytes: ", bytes)

}
