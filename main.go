package main

import (
	"c1k/client"
	"c1k/server"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
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
	var c_rate int
	var c_keepalive bool

	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print only the version",
	}

	app := &cli.App{
		Usage:   "Create more connection de tool, just test",
		Name:    "c1k",
		Version: "v0.0.1",
		Commands: []*cli.Command{
			{
				Name:  "server",
				Usage: "Just listen host and port",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "interface",
						// Value:       "eth0",
						// DefaultText: "eth0",
						Required:    true,
						Aliases:     []string{"i"},
						Usage:       "Set network interface name",
						Destination: &s_interface,
					},
					&cli.StringFlag{
						Name: "host",
						// Value:       "0.0.0.0",
						// DefaultText: "0.0.0.0",
						Required:    true,
						Aliases:     []string{"x"},
						Usage:       "Set interface ip",
						Destination: &s_host,
					},
					&cli.StringFlag{
						Name:        "port",
						Value:       "23456",
						DefaultText: "23456",
						Required:    true,
						Aliases:     []string{"p"},
						Usage:       "Server port, use [,] split",
						Destination: &s_port,
					},
				},
				Action: func(cCtx *cli.Context) error {
					fmt.Println(s_interface, s_host, s_port)
					server.HanderPacket(s_interface, s_host, s_port)
					return nil
				},
			},
			{
				Name:  "client",
				Usage: "create more conections for client",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:        "port",
						Value:       23456,
						DefaultText: "23456",
						Required:    true,
						Aliases:     []string{"p"},
						Usage:       "Set target port",
						Destination: &c_port,
					},
					&cli.StringFlag{
						Name:        "interface",
						Value:       "eth0",
						DefaultText: "eth0",
						Required:    true,
						Aliases:     []string{"i"},
						Usage:       "Set src network interface",
						Destination: &c_interface,
					},
					&cli.StringFlag{
						Name:        "host",
						Value:       "192.168.56.105",
						DefaultText: "192.168.56.105",
						Required:    true,
						Aliases:     []string{"x"},
						Usage:       "Set target host",
						Destination: &c_host,
					},
					&cli.StringFlag{
						Name:        "src",
						Value:       "192.168.56.1",
						DefaultText: "192.168.56.1",
						Required:    false,
						Aliases:     []string{"s"},
						Usage:       "Set src hosts ip or cidr",
						Destination: &c_src_hosts,
					},
					&cli.StringFlag{
						Name:        "srcport",
						Value:       "2000-62000",
						DefaultText: "2000-62000",
						Required:    false,
						Aliases:     []string{"b"},
						Usage:       "Src port range",
						Destination: &c_src_port_range,
					},
					&cli.IntFlag{
						Name:        "count",
						Value:       1,
						DefaultText: "1",
						Required:    false,
						Aliases:     []string{"c"},
						Usage:       "Connect count number",
						Destination: &c_count,
					},
					&cli.StringFlag{
						Name:        "exclude",
						Value:       "255.255.255.254/32",
						DefaultText: "255.255.255.254/32",
						Required:    false,
						Aliases:     []string{"e"},
						Usage:       "Exclude some network addresses",
						Destination: &c_src_exclude_hosts,
					},
					&cli.IntFlag{
						Name:        "rate",
						Value:       100,
						DefaultText: "100",
						Required:    false,
						Aliases:     []string{"r"},
						Usage:       "Connect rate (quantity / s)",
						Destination: &c_rate,
					},
					&cli.BoolFlag{
						Name:        "keepalive",
						DefaultText: "false",
						Required:    false,
						Aliases:     []string{"k"},
						Usage:       "Enable KeepAlive module",
						Destination: &c_keepalive,
					},
				},
				Action: func(cCtx *cli.Context) error {
					fmt.Println("create client: ", c_interface, c_count, c_src_hosts, c_src_port_range, c_host, c_port, c_rate)
					client.StartTask(c_interface, c_port, c_src_hosts, c_host, c_src_port_range, c_src_exclude_hosts, c_count, int32(c_rate), c_keepalive)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}
