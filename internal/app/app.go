package app

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"ebpf-patrol/internal/analyzer"
	"ebpf-patrol/internal/bpf"
	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/intent"
	"ebpf-patrol/internal/k8s"
	"ebpf-patrol/internal/policy"
	"ebpf-patrol/internal/webhook"

	"github.com/cilium/ebpf/ringbuf"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type App struct {
	objs          *bpf.Objects
	reader        *ringbuf.Reader
	analyzer      *analyzer.Analyzer
	watcher       *k8s.Watcher
	crdWatcher    *k8s.CRDWatcher
	informerSrc   *k8s.InformerSource
	webhookServer *webhook.Server
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
	Kubeconfig      string
	WebhookEnable   bool
	WebhookPort     int
	WebhookCertDir  string
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

	policyUpdater := bpf.NewPolicyMapUpdater(objs.HardDenyNames)
	hardDenyTargets := policies.HardDenyTargets()
	if err := policyUpdater.ReplaceHardDenyTargets(hardDenyTargets); err != nil {
		objs.Close()
		return nil, err
	}
	log.Printf("Injected %d hard deny policy targets into eBPF map", len(hardDenyTargets))

	app := &App{
		objs:     objs,
		reader:   rd,
		analyzer: analyzer.New(policies, intents, opts.ScopeMode),
	}

	if opts.K8sIntents {
		if err := app.setupK8sIntegration(opts, intents, objs); err != nil {
			objs.Close()
			return nil, err
		}
	}

	return app, nil
}

// setupK8sIntegration configures either kubectl polling or CRD informer mode.
func (a *App) setupK8sIntegration(opts Options, intents *intent.IntentSet, objs *bpf.Objects) error {
	updater := bpf.NewIntentFlagUpdater(objs.IntentFlags)

	switch opts.K8sMode {
	case "crd":
		return a.setupCRDMode(opts, intents, updater)
	case "kubectl", "":
		return a.setupKubectlMode(opts, intents, updater)
	default:
		return errors.New("k8s mode must be \"kubectl\" or \"crd\"")
	}
}

// setupKubectlMode is the existing kubectl get pods polling approach.
func (a *App) setupKubectlMode(opts Options, intents *intent.IntentSet, updater *bpf.IntentFlagUpdater) error {
	source := k8s.NewKubectlSource(opts.KubectlBinary)
	a.watcher = k8s.NewWatcher(source, intents, updater, opts.K8sSyncInterval, opts.K8sNodeName)
	log.Printf("Kubernetes intent materializer enabled: mode=kubectl interval=%s", opts.K8sSyncInterval)
	return nil
}

// setupCRDMode uses client-go informers for real-time WorkloadIntent CRD watching
// and pod informers for immediate pod event detection.
func (a *App) setupCRDMode(opts Options, intents *intent.IntentSet, updater *bpf.IntentFlagUpdater) error {
	config, err := buildKubeConfig(opts.Kubeconfig)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	// CRD watcher: WorkloadIntent 변경을 실시간으로 감지
	crdOnChange := func() {
		// CRD가 변경되면 intents를 갱신
		crdIntents := a.crdWatcher.GetIntents()
		intents.Intents = append(intents.Intents[:0], crdIntents...)
		log.Printf("crd: intent list updated from CRDs (%d intents)", len(crdIntents))
	}
	a.crdWatcher = k8s.NewCRDWatcher(dynamicClient, crdOnChange)

	// Pod informer: pod 변경을 실시간으로 감지
	podOnChange := func() {
		// Pod가 변경되면 watcher sync를 트리거
		// (별도 goroutine에서 debounce 처리됨)
	}
	a.informerSrc = k8s.NewInformerSource(clientset, podOnChange)

	// 기존 Watcher를 informer 소스로 연결 (폴링 대신 실시간)
	a.watcher = k8s.NewWatcher(a.informerSrc, intents, updater, opts.K8sSyncInterval, opts.K8sNodeName)

	// Webhook 서버 설정
	if opts.WebhookEnable {
		lookup := webhook.NewCRDIntentLookup()
		handler := webhook.NewHandler(lookup)
		a.webhookServer = webhook.NewServer(handler, opts.WebhookPort, opts.WebhookCertDir)
		log.Printf("Admission webhook enabled on port %d", opts.WebhookPort)
	}

	log.Printf("Kubernetes intent materializer enabled: mode=crd interval=%s", opts.K8sSyncInterval)
	return nil
}

func buildKubeConfig(kubeconfig string) (*rest.Config, error) {
	// 1. 명시적 kubeconfig 경로
	if kubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		log.Printf("Using kubeconfig: %s", kubeconfig)
		return config, nil
	}

	// 2. KUBECONFIG 환경변수
	if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", envKubeconfig)
		if err != nil {
			return nil, err
		}
		log.Printf("Using KUBECONFIG: %s", envKubeconfig)
		return config, nil
	}

	// 3. In-cluster config (Pod 안에서 실행 시)
	config, err := rest.InClusterConfig()
	if err == nil {
		log.Println("Using in-cluster Kubernetes config")
		return config, nil
	}

	// 4. 기본 ~/.kube/config
	home, _ := os.UserHomeDir()
	defaultPath := home + "/.kube/config"
	config, err = clientcmd.BuildConfigFromFlags("", defaultPath)
	if err != nil {
		return nil, errors.New("cannot determine Kubernetes config: set --kubeconfig, KUBECONFIG env, or run inside a pod")
	}
	log.Printf("Using default kubeconfig: %s", defaultPath)
	return config, nil
}

func (a *App) Run(ctx context.Context) error {
	// CRD watcher 시작 (있으면)
	if a.crdWatcher != nil {
		go a.crdWatcher.Start(ctx)
	}

	// Pod informer 시작 (있으면)
	if a.informerSrc != nil {
		go a.informerSrc.Start(ctx)
	}

	// kubectl 기반 watcher 시작 (있으면)
	if a.watcher != nil {
		go a.watcher.Run(ctx)
	}

	// Webhook 서버 시작 (있으면)
	if a.webhookServer != nil {
		go func() {
			if err := a.webhookServer.Start(ctx); err != nil {
				log.Printf("webhook server error: %v", err)
			}
		}()
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
