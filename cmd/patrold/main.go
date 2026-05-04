package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-patrol/internal/app"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (sudo)")
	}

	policyPath := "configs/policies.yaml"
	bpfObjPath := "gen/patrol_bpfel.o"

	application, err := app.New(policyPath, bpfObjPath)
	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}
	defer application.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\nShutting down...")
		cancel()
	}()

	log.Println("eBPF-PATROL started. Monitoring syscalls...")
	log.Println("Press Ctrl+C to stop.")

	if err := application.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Runtime error: %v", err)
	}

	log.Println("eBPF-PATROL stopped.")
}