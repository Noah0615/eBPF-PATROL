package crd

import "k8s.io/apimachinery/pkg/runtime"

// DeepCopyObject implements runtime.Object for WorkloadIntent.
func (in *WorkloadIntent) DeepCopyObject() runtime.Object {
	out := new(WorkloadIntent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another WorkloadIntent.
func (in *WorkloadIntent) DeepCopyInto(out *WorkloadIntent) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto copies WorkloadIntentSpec.
func (in *WorkloadIntentSpec) DeepCopyInto(out *WorkloadIntentSpec) {
	*out = *in

	// Selector
	if in.Selector.MatchLabels != nil {
		out.Selector.MatchLabels = make(map[string]string, len(in.Selector.MatchLabels))
		for k, v := range in.Selector.MatchLabels {
			out.Selector.MatchLabels[k] = v
		}
	}
	if in.Selector.MatchExpressions != nil {
		out.Selector.MatchExpressions = make([]SelectorExpression, len(in.Selector.MatchExpressions))
		for i, expr := range in.Selector.MatchExpressions {
			out.Selector.MatchExpressions[i] = expr
			if expr.Values != nil {
				out.Selector.MatchExpressions[i].Values = make([]string, len(expr.Values))
				copy(out.Selector.MatchExpressions[i].Values, expr.Values)
			}
		}
	}

	// NamespaceSelector
	if in.NamespaceSelector != nil {
		ns := *in.NamespaceSelector
		if ns.MatchLabels != nil {
			ns.MatchLabels = make(map[string]string, len(in.NamespaceSelector.MatchLabels))
			for k, v := range in.NamespaceSelector.MatchLabels {
				ns.MatchLabels[k] = v
			}
		}
		out.NamespaceSelector = &ns
	}

	// Slices
	if in.ExpectedProcesses != nil {
		out.ExpectedProcesses = make([]string, len(in.ExpectedProcesses))
		copy(out.ExpectedProcesses, in.ExpectedProcesses)
	}

	if in.AllowedPaths != nil {
		ap := &AllowedPaths{}
		if in.AllowedPaths.Read != nil {
			ap.Read = make([]string, len(in.AllowedPaths.Read))
			copy(ap.Read, in.AllowedPaths.Read)
		}
		if in.AllowedPaths.Write != nil {
			ap.Write = make([]string, len(in.AllowedPaths.Write))
			copy(ap.Write, in.AllowedPaths.Write)
		}
		out.AllowedPaths = ap
	}
}

// DeepCopyInto copies WorkloadIntentStatus.
func (in *WorkloadIntentStatus) DeepCopyInto(out *WorkloadIntentStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]IntentCondition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
}

// DeepCopyObject implements runtime.Object for WorkloadIntentList.
func (in *WorkloadIntentList) DeepCopyObject() runtime.Object {
	out := new(WorkloadIntentList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies WorkloadIntentList.
func (in *WorkloadIntentList) DeepCopyInto(out *WorkloadIntentList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]WorkloadIntent, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
