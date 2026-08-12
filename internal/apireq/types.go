// Package apireq measures and optionally limits AWS API requests.
package apireq

// Limits configures global request limits for a collection run. Zero disables
// the corresponding limit.
type Limits struct {
	MaxRequests          int64 `json:"maxRequests"`
	MaxRequestsPerMinute int   `json:"maxRequestsPerMinute"`
}

// Report is a concurrency-safe snapshot of request activity. LogicalCalls,
// Successes, and Failures describe completed SDK operation invocations.
// AttemptsSent describes calls handed to the HTTP transport; Retries is the
// subset marked as retry attempts by the SDK. APIErrors and TransportErrors
// classify failed transmitted attempts rather than pre-transport validation,
// signing, credential-provider, or hard-budget denials.
type Report struct {
	Limits             Limits          `json:"limits"`
	LogicalCalls       int64           `json:"logicalCalls"`
	AttemptsSent       int64           `json:"attemptsSent"`
	Retries            int64           `json:"retries"`
	Successes          int64           `json:"successes"`
	Failures           int64           `json:"failures"`
	APIErrors          int64           `json:"apiErrors"`
	TransportErrors    int64           `json:"transportErrors"`
	Throttles          int64           `json:"throttles"`
	LimiterWaitMillis  int64           `json:"limiterWaitMillis"`
	AttemptMillisTotal int64           `json:"attemptMillisTotal"`
	AttemptMillisMax   int64           `json:"attemptMillisMax"`
	LimitExceeded      bool            `json:"limitExceeded"`
	Services           []ServiceReport `json:"services"`
}

// ServiceReport summarizes calls to one normalized AWS service.
type ServiceReport struct {
	Name               string            `json:"name"`
	LogicalCalls       int64             `json:"logicalCalls"`
	AttemptsSent       int64             `json:"attemptsSent"`
	Retries            int64             `json:"retries"`
	Successes          int64             `json:"successes"`
	Failures           int64             `json:"failures"`
	APIErrors          int64             `json:"apiErrors"`
	TransportErrors    int64             `json:"transportErrors"`
	Throttles          int64             `json:"throttles"`
	LimiterWaitMillis  int64             `json:"limiterWaitMillis"`
	AttemptMillisTotal int64             `json:"attemptMillisTotal"`
	AttemptMillisMax   int64             `json:"attemptMillisMax"`
	Operations         []OperationReport `json:"operations"`
}

// OperationReport summarizes one normalized operation within a service.
type OperationReport struct {
	Name               string `json:"name"`
	LogicalCalls       int64  `json:"logicalCalls"`
	AttemptsSent       int64  `json:"attemptsSent"`
	Retries            int64  `json:"retries"`
	Successes          int64  `json:"successes"`
	Failures           int64  `json:"failures"`
	APIErrors          int64  `json:"apiErrors"`
	TransportErrors    int64  `json:"transportErrors"`
	Throttles          int64  `json:"throttles"`
	LimiterWaitMillis  int64  `json:"limiterWaitMillis"`
	AttemptMillisTotal int64  `json:"attemptMillisTotal"`
	AttemptMillisMax   int64  `json:"attemptMillisMax"`
}
