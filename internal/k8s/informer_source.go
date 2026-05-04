package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// InformerSource uses client-go shared informers to watch pods in real-time.
// This replaces the kubectl polling approach with event-driven updates,
// reducing latency from ~10s to milliseconds.
type InformerSource struct {
	clientset *kubernetes.Clientset
	factory   informers.SharedInformerFactory
	mu        sync.RWMutex
	pods      map[string]Pod // keyed by namespace/name
	onChange  func()         // callback when pod list changes
}

// NewInformerSource creates a pod source backed by client-go informers.
func NewInformerSource(clientset *kubernetes.Clientset, onChange func()) *InformerSource {
	src := &InformerSource{
		clientset: clientset,
		factory:   informers.NewSharedInformerFactory(clientset, 0),
		pods:      make(map[string]Pod),
		onChange:  onChange,
	}

	podInformer := src.factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			src.upsertPod(pod)
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			src.upsertPod(pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			src.deletePod(pod)
		},
	})

	return src
}

// Start begins watching pods. Blocks until ctx is cancelled.
func (s *InformerSource) Start(ctx context.Context) {
	s.factory.Start(ctx.Done())
	s.factory.WaitForCacheSync(ctx.Done())
	log.Println("k8s pod informer cache synced")
}

// ListPods implements PodSource, returning all cached pods.
func (s *InformerSource) ListPods(_ context.Context) ([]Pod, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Pod, 0, len(s.pods))
	for _, pod := range s.pods {
		result = append(result, pod)
	}
	return result, nil
}

func (s *InformerSource) upsertPod(corePod *corev1.Pod) {
	pod := convertCorePod(corePod)
	key := fmt.Sprintf("%s/%s", pod.Metadata.Namespace, pod.Metadata.Name)

	s.mu.Lock()
	s.pods[key] = pod
	s.mu.Unlock()

	if s.onChange != nil {
		s.onChange()
	}
}

func (s *InformerSource) deletePod(corePod *corev1.Pod) {
	key := fmt.Sprintf("%s/%s", corePod.Namespace, corePod.Name)

	s.mu.Lock()
	delete(s.pods, key)
	s.mu.Unlock()

	if s.onChange != nil {
		s.onChange()
	}
}

// convertCorePod converts a core/v1 Pod into our internal Pod type
// to maintain compatibility with the existing Watcher pipeline.
func convertCorePod(corePod *corev1.Pod) Pod {
	pod := Pod{
		Metadata: PodMetadata{
			Name:      corePod.Name,
			Namespace: corePod.Namespace,
			UID:       string(corePod.UID),
			Labels:    corePod.Labels,
		},
		Spec: PodSpec{
			NodeName: corePod.Spec.NodeName,
		},
		Status: PodStatus{
			Phase: string(corePod.Status.Phase),
		},
	}

	for _, cs := range corePod.Status.ContainerStatuses {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, ContainerStatus{
			Name:        cs.Name,
			ContainerID: cs.ContainerID,
		})
	}

	return pod
}

// NamespaceLabels fetches namespace labels for namespaceSelector matching.
func (s *InformerSource) NamespaceLabels(ctx context.Context, namespace string) (map[string]string, error) {
	ns, err := s.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get namespace %q: %w", namespace, err)
	}
	return ns.Labels, nil
}

// PodAnnotation reads an annotation from a running pod.
func PodAnnotation(raw json.RawMessage, key string) string {
	var obj struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	return obj.Metadata.Annotations[key]
}
