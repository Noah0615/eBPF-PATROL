package policy

import "testing"

func TestHardDenyNames(t *testing.T) {
	policies := &PolicySet{Policies: []Policy{
		{
			Name:   "deny-shadow",
			Type:   "open",
			Action: "deny",
			Match: MatchRule{PathContains: []string{
				"/etc/shadow",
				"/proc/kcore",
				"/var/run/docker.sock",
			}},
		},
		{
			Name:   "alert-mount",
			Type:   "mount",
			Action: "alert",
		},
	}}

	got := policies.HardDenyTargets()
	want := map[string]bool{
		"etc/shadow":       false,
		"proc/kcore":       false,
		"run/docker.sock": false,
	}

	for _, target := range got {
		key := target.Parent + "/" + target.Name
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}

	for name, seen := range want {
		if !seen {
			t.Fatalf("HardDenyTargets missing %q, got %#v", name, got)
		}
	}
}
