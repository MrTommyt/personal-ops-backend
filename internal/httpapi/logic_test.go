package httpapi

import "testing"

func TestMapActionToStatus(t *testing.T) {
	cases := map[string]string{
		"ack": "acknowledged",
		"resolve": "resolved",
		"approve": "approved",
		"reject": "rejected",
		"submit": "submitted",
		"close": "closed",
	}
	for action, expected := range cases {
		if got := mapActionToStatus(action); got != expected {
			t.Fatalf("%s => %s, expected %s", action, got, expected)
		}
	}
	if got := mapActionToStatus("unknown"); got != "" {
		t.Fatalf("expected empty status for unknown action")
	}
}

func TestGrafanaDedupeStable(t *testing.T) {
	labels := map[string]string{"service": "api", "env": "prod"}
	a := grafanaDedupe("rule1", labels)
	b := grafanaDedupe("rule1", labels)
	if a != b {
		t.Fatalf("dedupe key should be stable")
	}
}
