package app

import (
	"context"
	"log"

	"ebpf-patrol/internal/analyzer"
	"ebpf-patrol/internal/bpf"
	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/policy"
)

// policy: 규칙
// bpf: eBPF
// event: 사건
// analyzer: 사건이 규칙 위반인지 판단하는 분석가

type App struct {
	policies []policy.Policy
}
// 정책 파일(policies.yaml)을 읽어서 App 구조체에 담는 코드
func New() (*App, error) {
	policies, err := policy.LoadFromFile("configs/policies.yaml")
	if err != nil {
		return nil, err
	}

	return &App{
		policies: policies,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	objs, rd, err := bpf.LoadExecObjects()
	if err != nil {
		return err
	}
	defer objs.Close()
	defer rd.Close()

	az := analyzer.New(a.policies)

	log.Println("patrold started") // 시작 로그

	// 무한 반복 (계속 감시!)
	for {
		select {
		case <-ctx.Done():
			log.Println("patrold stopped")
			return nil
		default:
			ev, err := event.ReadExecEvent(rd)
			if err != nil {
				continue
			}
			az.HandleExec(ev)
		}
	}
}