package k8s

import (
	"context"
	"log"
	"strings"
	"time"

	"ebpf-patrol/internal/intent"
)

type Watcher struct {
	source   PodSource
	intents  *intent.IntentSet
	updater  IntentFlagUpdater
	interval time.Duration
	nodeName string
	root     string
}

type IntentFlagUpdater interface {
	UpdateIntentFlags(map[uint64]intent.MaterializedIntent) error
}

func NewWatcher(source PodSource, intents *intent.IntentSet, updater IntentFlagUpdater, interval time.Duration, nodeName string) *Watcher {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Watcher{
		source:   source,
		intents:  intents,
		updater:  updater,
		interval: interval,
		nodeName: nodeName,
		root:     "/sys/fs/cgroup",
	}
}

func (w *Watcher) Run(ctx context.Context) {
	w.sync(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sync(ctx)
		}
	}
}

func (w *Watcher) sync(ctx context.Context) {
	if w.source == nil || w.intents == nil {
		return
	}

	pods, err := w.source.ListPods(ctx)
	if err != nil {
		log.Printf("k8s intent sync failed: %v", err)
		return
	}

	type podIntent struct {
		pod    Pod
		intent intent.Intent
	}

	byUID := make(map[string]podIntent)
	var uids []string
	for _, pod := range pods {
		if !w.shouldUsePod(pod) {
			continue
		}

		matched, ok := w.intents.MatchByLabels(pod.Metadata.Labels)
		if !ok {
			continue
		}

		uid := pod.Metadata.UID
		byUID[uid] = podIntent{pod: pod, intent: matched}
		uids = append(uids, uid)
	}

	cgroups, err := ScanCgroups(w.root, uids)
	if err != nil {
		log.Printf("k8s cgroup scan failed: %v", err)
		return
	}

	next := make(map[uint64]intent.MaterializedIntent)
	now := time.Now().Unix()
	for uid, matches := range cgroups {
		info, ok := byUID[uid]
		if !ok {
			continue
		}

		containerID := firstContainerID(info.pod)
		for _, match := range matches {
			materializedAt := now
			if existing, ok := w.intents.LookupMaterialized(match.CgroupID); ok {
				materializedAt = existing.MaterializedAt
			}

			next[match.CgroupID] = intent.MaterializedIntent{
				Intent:         info.intent,
				PodName:        info.pod.Metadata.Name,
				Namespace:      info.pod.Metadata.Namespace,
				PodUID:         uid,
				ContainerID:    containerID,
				CgroupPath:     match.Path,
				MaterializedBy: "kubernetes",
				MaterializedAt: materializedAt,
			}
		}
	}

	w.intents.ReplaceMaterialized(next)
	if w.updater != nil {
		if err := w.updater.UpdateIntentFlags(next); err != nil {
			log.Printf("k8s intent map update failed: %v", err)
		}
	}
	log.Printf("k8s intent sync: pods=%d materialized_cgroups=%d bpf_map=updated", len(byUID), len(next))
}

func (w *Watcher) shouldUsePod(pod Pod) bool {
	if pod.Metadata.UID == "" {
		return false
	}
	if pod.Status.Phase != "" && pod.Status.Phase != "Running" {
		return false
	}
	if w.nodeName != "" && pod.Spec.NodeName != "" && pod.Spec.NodeName != w.nodeName {
		return false
	}
	return true
}

func firstContainerID(pod Pod) string {
	for _, status := range pod.Status.ContainerStatuses {
		if status.ContainerID == "" {
			continue
		}
		parts := strings.Split(status.ContainerID, "://")
		if len(parts) == 2 {
			return parts[1]
		}
		return status.ContainerID
	}
	return ""
}
