// Package webhook implements a Kubernetes Validating Admission Webhook
// that pre-binds WorkloadIntents to pods at creation time.
//
// 핵심 목적:
// 1. Pod 생성 시 어떤 WorkloadIntent가 적용될지 미리 결정 (annotation 주입)
// 2. 의도가 정의되지 않은 pod에 대해 경고 → 관리자에게 빠진 intent를 알려 FP 감소
// 3. requireApproval이 true인 intent에 대해 승인 annotation 확인
package webhook

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	crdtypes "ebpf-patrol/internal/k8s/crd"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Annotations added by the webhook
	AnnotationMatchedIntent = "patrol.ebpf.io/matched-intent"
	AnnotationIntentMode    = "patrol.ebpf.io/enforcement-mode"
	AnnotationApprovedBy    = "patrol.ebpf.io/approved-by"
	AnnotationNoIntent      = "patrol.ebpf.io/no-intent-warning"
)

// IntentLookup is the interface the webhook uses to find matching intents.
type IntentLookup interface {
	MatchPodLabels(labels map[string]string) (*crdtypes.WorkloadIntent, bool)
}

// Handler processes admission review requests for pod validation.
type Handler struct {
	lookup IntentLookup
}

// NewHandler creates a new webhook handler with the given intent lookup.
func NewHandler(lookup IntentLookup) *Handler {
	return &Handler{lookup: lookup}
}

// HandleValidate is the HTTP handler for /validate-pod
func (h *Handler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		log.Printf("webhook: failed to decode admission review: %v", err)
		http.Error(w, "failed to decode request", http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "empty admission request", http.StatusBadRequest)
		return
	}

	response := h.validate(review.Request)

	review.Response = response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		log.Printf("webhook: failed to encode response: %v", err)
	}
}

func (h *Handler) validate(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Pod 이외의 리소스는 무조건 허용
	if req.Kind.Kind != "Pod" {
		return allowed("not a pod")
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		log.Printf("webhook: failed to unmarshal pod: %v", err)
		return allowed("failed to parse pod, allowing by default")
	}

	labels := pod.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	// WorkloadIntent 매칭
	matchedIntent, found := h.lookup.MatchPodLabels(labels)

	if !found {
		// Intent가 없는 pod: 경고는 하되 거부하지 않는다 (FP 방지).
		// 관리자에게 intent를 정의하라는 신호를 준다.
		log.Printf("webhook: WARN pod %s/%s has no matching WorkloadIntent (labels=%v)",
			req.Namespace, pod.Name, labels)

		return allowedWithWarning(
			fmt.Sprintf("No WorkloadIntent matches pod labels %v. "+
				"Consider creating a WorkloadIntent CRD to define expected behavior.", labels),
		)
	}

	log.Printf("webhook: pod %s/%s matched WorkloadIntent %s/%s (mode=%s priority=%d)",
		req.Namespace, pod.Name, matchedIntent.Namespace, matchedIntent.Name,
		matchedIntent.Spec.EnforcementMode, matchedIntent.Spec.Priority)

	// requireApproval 확인
	if matchedIntent.Spec.RequireApproval {
		approvedBy := pod.Annotations[AnnotationApprovedBy]
		if approvedBy == "" {
			msg := fmt.Sprintf(
				"WorkloadIntent %q requires approval annotation %q on the pod",
				matchedIntent.Name, AnnotationApprovedBy,
			)
			log.Printf("webhook: DENY pod %s/%s — %s", req.Namespace, pod.Name, msg)

			// enforce 모드에서만 실제 거부
			if matchedIntent.Spec.EnforcementMode == "enforce" {
				return denied(msg)
			}
			// audit/learn 모드에서는 경고만
			return allowedWithWarning("[audit] " + msg)
		}
		log.Printf("webhook: pod %s/%s approved by %q", req.Namespace, pod.Name, approvedBy)
	}

	// securityContext 모순 검증
	if warnings := h.validateSecurityContext(&pod, matchedIntent); len(warnings) > 0 {
		log.Printf("webhook: WARN pod %s/%s security context issues: %v",
			req.Namespace, pod.Name, warnings)
		return allowedWithWarnings(warnings)
	}

	// 매칭 성공: JSON patch로 annotation 추가
	patches := []jsonPatch{
		{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: ensureAnnotationMap(pod.Annotations, map[string]string{
				AnnotationMatchedIntent: matchedIntent.Name,
				AnnotationIntentMode:    matchedIntent.Spec.EnforcementMode,
			}),
		},
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		log.Printf("webhook: failed to marshal patch: %v", err)
		return allowed("patch creation failed")
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patchBytes,
		Result: &metav1.Status{
			Message: fmt.Sprintf("matched WorkloadIntent %q", matchedIntent.Name),
		},
	}
}

// validateSecurityContext checks if the pod's security context contradicts
// the matched intent. This catches misconfigurations early.
func (h *Handler) validateSecurityContext(pod *corev1.Pod, wi *crdtypes.WorkloadIntent) []string {
	var warnings []string

	for _, container := range pod.Spec.Containers {
		sc := container.SecurityContext
		if sc == nil {
			continue
		}

		// Pod가 privileged인데 intent가 privilege를 허용하지 않는 경우
		if sc.Privileged != nil && *sc.Privileged && !wi.Spec.AllowPrivilegeOps {
			warnings = append(warnings,
				fmt.Sprintf("container %q is privileged but WorkloadIntent %q disallows privilege ops",
					container.Name, wi.Name))
		}

		// Capabilities에 SYS_ADMIN이 있는데 allowPrivilegeOps가 false인 경우
		if sc.Capabilities != nil {
			for _, cap := range sc.Capabilities.Add {
				if string(cap) == "SYS_ADMIN" && !wi.Spec.AllowPrivilegeOps {
					warnings = append(warnings,
						fmt.Sprintf("container %q adds CAP_SYS_ADMIN but WorkloadIntent %q disallows privilege ops",
							container.Name, wi.Name))
				}
				if string(cap) == "SYS_PTRACE" && !wi.Spec.AllowPrivilegeOps {
					warnings = append(warnings,
						fmt.Sprintf("container %q adds CAP_SYS_PTRACE but WorkloadIntent %q disallows privilege ops",
							container.Name, wi.Name))
				}
			}
		}
	}

	// HostPID나 HostNetwork를 쓰는데 namespace ops를 불허한 경우
	if pod.Spec.HostPID && !wi.Spec.AllowNamespaceOps {
		warnings = append(warnings,
			fmt.Sprintf("pod uses hostPID but WorkloadIntent %q disallows namespace ops", wi.Name))
	}
	if pod.Spec.HostNetwork && !wi.Spec.AllowNamespaceOps {
		warnings = append(warnings,
			fmt.Sprintf("pod uses hostNetwork but WorkloadIntent %q disallows namespace ops", wi.Name))
	}

	return warnings
}

type jsonPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func ensureAnnotationMap(existing map[string]string, add map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range existing {
		result[k] = v
	}
	for k, v := range add {
		result[k] = v
	}
	return result
}

func allowed(reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Result:  &metav1.Status{Message: reason},
	}
}

func denied(reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Message: reason,
			Reason:  metav1.StatusReasonForbidden,
		},
	}
}

func allowedWithWarning(warning string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed:  true,
		Warnings: []string{warning},
		Result:   &metav1.Status{Message: warning},
	}
}

func allowedWithWarnings(warnings []string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed:  true,
		Warnings: warnings,
		Result:   &metav1.Status{Message: strings.Join(warnings, "; ")},
	}
}
