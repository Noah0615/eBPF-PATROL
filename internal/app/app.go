package app

import (
	"context"
	"errors"
	"log"
	"time"

	"ebpf-patrol/internal/analyzer"
	"ebpf-patrol/internal/bpf"
	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/intent"
	"ebpf-patrol/internal/k8s"
	"ebpf-patrol/internal/policy"

	"github.com/cilium/ebpf/ringbuf"
)

type App struct {
	objs     *bpf.Objects
	reader   *ringbuf.Reader
	analyzer *analyzer.Analyzer
	watcher  *k8s.Watcher
}

type Options struct {
	PolicyPath      string
	IntentPath      string
	BPFObjectPath   string
	ScopeMode       string
	K8sIntents      bool
	K8sMode         string
	KubectlBinary   string
	K8sNodeName     string
	K8sSyncInterval time.Duration
}

func New(opts Options) (*App, error) {
	policies, err := policy.LoadPolicies(opts.PolicyPath)
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d policies from %s", len(policies.Policies), opts.PolicyPath)

	intents, err := intent.Load(opts.IntentPath)
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d intents from %s", len(intents.Intents), opts.IntentPath)

	objs, rd, err := bpf.LoadObjects(opts.BPFObjectPath)
	if err != nil {
		return nil, err
	}

	log.Println("eBPF programs loaded and attached successfully")

	var watcher *k8s.Watcher
	if opts.K8sIntents {
		if opts.K8sMode == "" {
			opts.K8sMode = "kubectl"
		}
		if opts.K8sMode != "kubectl" {
			return nil, errors.New("only k8s mode \"kubectl\" is implemented")
		}
		source := k8s.NewKubectlSource(opts.KubectlBinary)
		watcher = k8s.NewWatcher(source, intents, opts.K8sSyncInterval, opts.K8sNodeName)
		log.Printf("Kubernetes intent materializer enabled: mode=%s interval=%s", opts.K8sMode, opts.K8sSyncInterval)
	}

	return &App{
		objs:     objs,
		reader:   rd,
		analyzer: analyzer.New(policies, intents, opts.ScopeMode),
		watcher:  watcher,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	if a.watcher != nil {
		go a.watcher.Run(ctx)
	}

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
