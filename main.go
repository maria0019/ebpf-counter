package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}

	fmt.Printf("Found [%d] interfaces", len(ifaces))
	for _, i := range ifaces {
		go runForInterface(i.Name)
	}

	<-stop
}

func runForInterface(ifName string) {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	log.Printf("Run for [%s] interface", ifName)
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifName, err)
	}

	// Attach count_packets to the network interface.
	linkToInterface, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer linkToInterface.Close()

	log.Printf("Counting incoming packets on %s..", ifName)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64

			if err := objs.PktCount.Lookup(uint32(0), &count); err != nil {
				log.Fatal("Map lookup:", err)
			}
			if count > 0 {
				log.Printf("[%s] Received %d packets", ifName, count)
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
