package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native bpf ebpf=program.c -- -I../bpf/headers

const (
	// Default port to drop to
	defaultPort = 4040
)

func main() {

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var coll drop_tcp_portObjects
	if err := loadDrop_tcp_portObjects(&coll, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer coll.Close()

	ifname := "io" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach drop_tcp_packets to the network interface.
	tLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.DropTcpPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer tLink.Close()

	log.Printf("Dropping TCP packets on port %d on %s..", defaultPort, ifname)

	// Update the port number in the drop_port map
	dport := defaultPort
	if len(os.Args) > 1 {
		var portArg int
		if _, err := fmt.Sscanf(os.Args[1], "%d", &portArg); err == nil {
			dport = portArg
		}
	}

	key := uint32(0)
	value := uint16(dport)
	if err := coll.DropPort.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatal("Updating drop_port map:", err)
	}

	log.Printf("Configured to drop TCP packets on port %d", dport)

	<-stopper
	log.Print("Received signal, exiting..")
}
