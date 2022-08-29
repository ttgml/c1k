package main

import (
	"c1k/client"
	"c1k/server"
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"
)

func main() {
	var s_interface string
	var s_host string
	var s_port string
	var c_port int
	var c_interface string
	var c_host string
	var c_count int
	var c_src_port_range string
	var c_src_hosts string
	var c_src_exclude_hosts string
	app := &cli.App{
		Usage: "Create more connection de tool",
		Commands: []*cli.Command{
			{
				Name:    "server",
				Usage:   "Just listen host and port",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "interface",
						Value: "eth0",
						DefaultText: "eth0",
						Required: false,
						Aliases: []string{"i"},
						Usage: "set network interface",
						Destination: &s_interface,
					},
					&cli.StringFlag{
						Name:  "host",
						Value: "0.0.0.0",
						DefaultText: "0.0.0.0",
						Required: false,
						Aliases: []string{"x"},
						Usage: "set network host/ip",
						Destination: &s_host,
					},
					&cli.StringFlag{
						Name:  "port",
						Value: "23456",
						DefaultText: "23456",
						Required: false,
						Aliases: []string{"p"},
						Usage: "set network port",
						Destination: &s_port,
					},
				},
				Action: func(cCtx *cli.Context) error {
					fmt.Println(s_interface,s_host,s_port)
					server.HanderPacket(s_interface,s_host,s_port)
					return nil
				},
			},
			{
				Name:    "client",
				Usage:   "create more conections for client",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "port",
						Value: 23456,
						DefaultText: "23456",
						Required: false,
						Aliases: []string{"p"},
						Usage: "set target port",
						Destination: &c_port,
					},
					&cli.StringFlag{
						Name: "interface",
						Value: "eth0",
						DefaultText: "eth0",
						Required: false,
						Aliases: []string{"i"},
						Usage: "set src network interface",
						Destination: &c_interface,
					},
					&cli.StringFlag{
						Name: "host",
						Value: "192.168.56.105",
						DefaultText: "192.168.56.105",
						Required: false,
						Aliases: []string{"x"},
						Usage: "set target host",
						Destination: &c_host,
					},
					&cli.StringFlag{
						Name: "src",
						Value: "192.168.56.1",
						DefaultText: "192.168.56.1",
						Required: false,
						Aliases: []string{"s"},
						Usage: "set src hosts ip or cidr",
						Destination: &c_src_hosts,
					},
					&cli.StringFlag{
						Name: "srcport",
						Value: "1024-61024",
						DefaultText: "1024-61024",
						Required: false,
						Aliases: []string{"b"},
						Usage: "set src port range",
						Destination: &c_src_port_range,
					},
					&cli.IntFlag{
						Name: "count",
						Value: 1,
						DefaultText: "1",
						Required: false,
						Aliases: []string{"c"},
						Usage: "set connect count number",
						Destination: &c_count,
					},
					&cli.StringFlag{
						Name: "exclude",
						Value: "255.255.255.254/32",
						DefaultText: "1",
						Required: false,
						Aliases: []string{"e"},
						Usage: "Exclude some network addresses",
						Destination: &c_src_exclude_hosts,
					},
				},
				Action: func(cCtx *cli.Context) error {
					fmt.Println("create client: ", c_interface,c_count,c_src_hosts,c_src_port_range,c_host,c_port)
					//buildFirstSYNPacket(192.168.56.1,)



					go client.HanderPacket(c_interface,c_port)
					time.Sleep(time.Second*2)
					client.ProcessTask(c_src_hosts,c_interface,c_host,c_src_port_range,c_src_exclude_hosts,c_port,c_count)
					//for {
					//	//client.BuildOnlySYNPacket()
					//}
					time.Sleep(100*time.Second)
					return nil
				},

			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}

func Bytes2Bits(data []byte) []int {
	dst := make([]int, 0)
	for _, v := range data {
		for i := 0; i < 8; i++ {
			move := uint(7 - i)
			dst = append(dst, int((v>>move)&1))
		}
	}
	return dst
}
