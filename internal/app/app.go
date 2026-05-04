package app

import (
	"context"
	"errors"
	"log"

	"ebpf-patrol/internal/analyzer"
	"ebpf-patrol/internal/bpf"
	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/intent"
	"ebpf-patrol/internal/policy"

	"github.com/cilium/ebpf/ringbuf"
)

type App struct {
	objs     *bpf.Objects
	reader   *ringbuf.Reader
	analyzer *analyzer.Analyzer
}

func New(policyPath, intentPath, bpfObjPath, scopeMode string) (*App, error) {
	policies, err := policy.LoadPolicies(policyPath)
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d policies from %s", len(policies.Policies), policyPath)

	intents, err := intent.Load(intentPath)
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d intents from %s", len(intents.Intents), intentPath)

	objs, rd, err := bpf.LoadObjects(bpfObjPath)
	if err != nil {
		return nil, err
	}

	log.Println("eBPF programs loaded and attached successfully")

	return &App{
		objs:     objs,
		reader:   rd,
		analyzer: analyzer.New(policies, intents, scopeMode),
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.analyzer.PrintStats()
			return ctx.Err()
		default:
		}

		e, err := event.ReadEvent(a.reader)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("read event error: %v", err)
			continue
		}

		a.analyzer.Analyze(e)
	}
}

func (a *App) Close() {
	if a.reader != nil {
		_ = a.reader.Close()
	}
	if a.objs != nil {
		a.objs.Close()
	}
}
