package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"ebpf-patrol/internal/app"
)

// 앱을 만들고 -> 실행하고 -> 중간에 종료 신호 오면 깔끔하게 멈추는 코드
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New()
	if err != nil {
		log.Fatalf("new app: %v", err)
	}

	if err := a.Run(ctx); err != nil {
		log.Fatalf("run app: %v", err)
	}
}