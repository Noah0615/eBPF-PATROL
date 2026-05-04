package verdict

type PolicyVerdict string

const (
	PolicyAllow      PolicyVerdict = "ALLOW"
	PolicyDeny       PolicyVerdict = "DENY"
	PolicySuspicious PolicyVerdict = "SUSPICIOUS"
)

type IntentVerdict string

const (
	IntentAllow   IntentVerdict = "ALLOW"
	IntentDeny    IntentVerdict = "DENY"
	IntentUnknown IntentVerdict = "UNKNOWN"
)

type ContextVerdict string

const (
	ContextNormal     ContextVerdict = "NORMAL"
	ContextSuspicious ContextVerdict = "SUSPICIOUS"
	ContextAnomalous  ContextVerdict = "ANOMALOUS"
)

type FinalVerdict string

const (
	FinalAllow FinalVerdict = "ALLOW"
	FinalAlert FinalVerdict = "ALERT"
	FinalDeny  FinalVerdict = "DENY"
	FinalKill  FinalVerdict = "KILL"
)

type PolicyResult struct {
	Verdict     PolicyVerdict
	Reason      string
	MatchedRule string
	Severity    string
}

type IntentResult struct {
	Verdict       IntentVerdict
	Reason        string
	MatchedIntent string
}

type ContextResult struct {
	Verdict ContextVerdict
	Reason  string
	Score   float64
}

type Decision struct {
	Final      FinalVerdict
	Confidence float64
	Reason     string
	Policy     PolicyResult
	Intent     IntentResult
	Context    ContextResult
}
