package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-patrol/internal/app"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (sudo)")
	}

	policyPath := flag.String("policy", "configs/policies.yaml", "path to policy YAML")
	intentPath := flag.String("intent", "configs/intents.yaml", "path to intent YAML")
	bpfObjPath := flag.String("bpf", "gen/patrol_bpfel.o", "path to compiled eBPF object")
	scopeMode := flag.String("scope", "containers", "analysis scope: containers or all")
	k8sIntents := flag.Bool("k8s-intents", false, "enable Kubernetes label-to-cgroup intent materialization")
	k8sMode := flag.String("k8s-mode", "kubectl", "Kubernetes intent source mode: kubectl or crd")
	kubectlBinary := flag.String("kubectl", "kubectl", "kubectl binary path")
	k8sNodeName := flag.String("k8s-node", "", "optional Kubernetes node name filter")
	k8sSyncInterval := flag.Duration("k8s-sync-interval", 10*time.Second, "Kubernetes intent sync interval")

	// CRD 모드 옵션
	kubeconfig := flag.String("kubeconfig", "", "path to kubeconfig (for out-of-cluster mode)")

	// Admission Webhook 옵션
	webhookEnable := flag.Bool("webhook-enable", false, "enable validating admission webhook server")
	webhookPort := flag.Int("webhook-port", 8443, "webhook HTTPS listen port")
	webhookCertDir := flag.String("webhook-cert-dir", "/certs", "directory containing tls.crt and tls.key")

	flag.Parse()

	application, err := app.New(app.Options{
		PolicyPath:      *policyPath,
		IntentPath:      *intentPath,
		BPFObjectPath:   *bpfObjPath,
		ScopeMode:       *scopeMode,
		K8sIntents:      *k8sIntents,
		K8sMode:         *k8sMode,
		KubectlBinary:   *kubectlBinary,
		K8sNodeName:     *k8sNodeName,
		K8sSyncInterval: *k8sSyncInterval,
		Kubeconfig:      *kubeconfig,
		WebhookEnable:   *webhookEnable,
		WebhookPort:     *webhookPort,
		WebhookCertDir:  *webhookCertDir,
	})
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
