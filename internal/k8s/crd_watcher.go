// Package k8s — crd_watcher.go
// WorkloadIntent CRD를 watch하여 변경 시 즉시 intent를 갱신한다.
// kubectl 폴링 대비 지연 시간이 밀리초 단위로 줄어들어 의도-실행 간극에서
// 발생하는 false negative를 방지한다.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	crdtypes "ebpf-patrol/internal/k8s/crd"
	"ebpf-patrol/internal/intent"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

var workloadIntentGVR = schema.GroupVersionResource{
	Group:    crdtypes.GroupName,
	Version:  crdtypes.Version,
	Resource: crdtypes.Resource,
}

// CRDWatcher watches WorkloadIntent custom resources and converts them
// into internal Intent objects. It replaces the YAML-only intent loading
// with a live, reactive approach.
type CRDWatcher struct {
	dynamicClient dynamic.Interface
	mu            sync.RWMutex
	intents       map[string]intent.Intent // key: namespace/name
	onChange      func()                   // callback when intents change
}

// NewCRDWatcher creates a CRD watcher for WorkloadIntent resources.
func NewCRDWatcher(dynamicClient dynamic.Interface, onChange func()) *CRDWatcher {
	return &CRDWatcher{
		dynamicClient: dynamicClient,
		intents:       make(map[string]intent.Intent),
		onChange:      onChange,
	}
}

// Start begins watching WorkloadIntent CRDs.
func (w *CRDWatcher) Start(ctx context.Context) {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(w.dynamicClient, 30*time.Second)
	informer := factory.ForResource(workloadIntentGVR).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			w.handleCRDEvent(obj, "add")
		},
		UpdateFunc: func(_, newObj interface{}) {
			w.handleCRDEvent(newObj, "update")
		},
		DeleteFunc: func(obj interface{}) {
			uns, ok := obj.(*unstructured.Unstructured)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				uns, ok = tombstone.Obj.(*unstructured.Unstructured)
				if !ok {
					return
				}
			}
			key := fmt.Sprintf("%s/%s", uns.GetNamespace(), uns.GetName())
			w.mu.Lock()
			delete(w.intents, key)
			w.mu.Unlock()
			log.Printf("crd watcher: WorkloadIntent %s deleted", key)
			if w.onChange != nil {
				w.onChange()
			}
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	log.Println("WorkloadIntent CRD informer cache synced")
}

func (w *CRDWatcher) handleCRDEvent(obj interface{}, action string) {
	uns, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}

	wi, err := unstructuredToWorkloadIntent(uns)
	if err != nil {
		log.Printf("crd watcher: failed to parse WorkloadIntent: %v", err)
		return
	}

	converted := crdtypes.ToIntent(wi)
	key := fmt.Sprintf("%s/%s", wi.Namespace, wi.Name)

	w.mu.Lock()
	w.intents[key] = converted
	w.mu.Unlock()

	log.Printf("crd watcher: WorkloadIntent %s %sd (mode=%s priority=%d grace=%ds)",
		key, action, wi.Spec.EnforcementMode, wi.Spec.Priority, wi.Spec.GracePeriodSeconds)

	if w.onChange != nil {
		w.onChange()
	}
}

// GetIntents returns all currently known intents from CRDs.
func (w *CRDWatcher) GetIntents() []intent.Intent {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]intent.Intent, 0, len(w.intents))
	for _, i := range w.intents {
		result = append(result, i)
	}

	// 오탐 감소: priority 순으로 정렬하여 높은 우선순위가 먼저 매칭되게 한다.
	sort.Slice(result, func(a, b int) bool {
		return result[a].Meta.Priority > result[b].Meta.Priority
	})

	return result
}

// MatchPodLabels finds the best-matching WorkloadIntent for the given pod labels.
// Returns the highest-priority matching intent (reduces ambiguity → reduces FP).
func (w *CRDWatcher) MatchPodLabels(podLabels map[string]string) (intent.Intent, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var best *intent.Intent
	bestPriority := -1

	for _, i := range w.intents {
		if selectorMatchesLabels(i.Selector.MatchLabels, podLabels) {
			if i.Meta.Priority > bestPriority {
				copied := i
				best = &copied
				bestPriority = i.Meta.Priority
			}
		}
	}

	if best != nil {
		return *best, true
	}
	return intent.Intent{}, false
}

func selectorMatchesLabels(selector map[string]string, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, want := range selector {
		if labels[key] != want {
			return false
		}
	}
	return true
}

func unstructuredToWorkloadIntent(uns *unstructured.Unstructured) (*crdtypes.WorkloadIntent, error) {
	data, err := json.Marshal(uns.Object)
	if err != nil {
		return nil, fmt.Errorf("marshal unstructured: %w", err)
	}

	var wi crdtypes.WorkloadIntent
	if err := json.Unmarshal(data, &wi); err != nil {
		return nil, fmt.Errorf("unmarshal to WorkloadIntent: %w", err)
	}

	// TypeMeta와 ObjectMeta는 unstructured에서 직접 가져온다
	wi.Name = uns.GetName()
	wi.Namespace = uns.GetNamespace()
	wi.UID = uns.GetUID()

	return &wi, nil
}

// UpdateCRDStatus updates the status subresource of a WorkloadIntent CRD.
func (w *CRDWatcher) UpdateCRDStatus(ctx context.Context, namespace, name string, matchedPods, materializedCgroups int) error {
	status := map[string]interface{}{
		"matchedPods":         matchedPods,
		"materializedCgroups": materializedCgroups,
		"lastSyncTime":        metav1.Now().Format(time.RFC3339),
		"conditions": []map[string]interface{}{
			{
				"type":               "Synced",
				"status":             "True",
				"lastTransitionTime": metav1.Now().Format(time.RFC3339),
				"reason":             "IntentMaterialized",
				"message":            fmt.Sprintf("Materialized to %d cgroups from %d pods", materializedCgroups, matchedPods),
			},
		},
	}

	patch := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": crdtypes.GroupName + "/" + crdtypes.Version,
			"kind":       crdtypes.Kind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"status": status,
		},
	}

	_, err := w.dynamicClient.Resource(workloadIntentGVR).Namespace(namespace).
		UpdateStatus(ctx, patch, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update WorkloadIntent status %s/%s: %w", namespace, name, err)
	}
	return nil
}

// Ensure runtime import is used (for future deep-copy needs).
var _ = runtime.Object(nil)
