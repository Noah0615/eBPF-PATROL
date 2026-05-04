// Package webhook — lookup.go
// CRDWatcher를 IntentLookup 인터페이스에 연결하는 어댑터.
package webhook

import (
	"sort"
	"sync"

	crdtypes "ebpf-patrol/internal/k8s/crd"
)

// CRDIntentLookup implements IntentLookup by querying stored WorkloadIntents.
type CRDIntentLookup struct {
	mu      sync.RWMutex
	intents []*crdtypes.WorkloadIntent
}

// NewCRDIntentLookup creates a new CRD-backed intent lookup.
func NewCRDIntentLookup() *CRDIntentLookup {
	return &CRDIntentLookup{}
}

// Update replaces the current set of WorkloadIntents.
func (l *CRDIntentLookup) Update(intents []*crdtypes.WorkloadIntent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.intents = make([]*crdtypes.WorkloadIntent, len(intents))
	copy(l.intents, intents)

	// Priority 높은 순으로 정렬
	sort.Slice(l.intents, func(a, b int) bool {
		return l.intents[a].Spec.Priority > l.intents[b].Spec.Priority
	})
}

// MatchPodLabels finds the highest-priority WorkloadIntent matching the pod labels.
func (l *CRDIntentLookup) MatchPodLabels(labels map[string]string) (*crdtypes.WorkloadIntent, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, wi := range l.intents {
		if crdtypes.MatchesPodLabels(wi, labels) {
			return wi, true
		}
	}
	return nil, false
}
