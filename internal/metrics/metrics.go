// Package metrics defines all Prometheus metrics for the gateway.
//
// All metrics are registered once in an init-style block and then referenced
// throughout the codebase. Keeping them here avoids scattered registrations
// and makes it easy to see every observable signal at a glance.
//
// Metrics exposed:
//   gateway_requests_total          counter   by tenant, status_code, path
//   gateway_request_duration_seconds histogram by tenant, path
//   guardrail_blocks_total          counter   by tenant, stage (input/output)
//   policy_evaluations_total        counter   by tenant, verdict (block/tag/log/pass)
//   stream_aborts_total             counter   by tenant
//   rate_limit_hits_total           counter   by tenant, kind (rate/quota)
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RequestsTotal counts every HTTP request that reaches the gateway.
// Labels: tenant, status_code (e.g. "200", "403", "429"), path ("/v1/complete")
var RequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gateway_requests_total",
		Help: "Total number of requests handled by the gateway.",
	},
	[]string{"tenant", "status_code", "path"},
)

// RequestDuration tracks end-to-end request latency.
// Labels: tenant, path
var RequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "gateway_request_duration_seconds",
		Help:    "End-to-end request duration in seconds.",
		Buckets: prometheus.DefBuckets, // .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
	},
	[]string{"tenant", "path"},
)

// GuardrailBlocksTotal counts requests blocked by the guardrail scanner.
// Labels: tenant, stage ("input" or "output")
var GuardrailBlocksTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "guardrail_blocks_total",
		Help: "Total requests blocked by the guardrail scanner.",
	},
	[]string{"tenant", "stage"},
)

// PolicyEvaluationsTotal counts policy engine evaluations.
// Labels: tenant, verdict ("block", "tag", "log", "pass")
var PolicyEvaluationsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "policy_evaluations_total",
		Help: "Total policy evaluations by verdict.",
	},
	[]string{"tenant", "verdict"},
)

// StreamAbortsTotal counts streams aborted by the output scanner.
// Labels: tenant
var StreamAbortsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "stream_aborts_total",
		Help: "Total streams aborted due to unsafe output detected.",
	},
	[]string{"tenant"},
)

// RateLimitHitsTotal counts requests rejected by rate limiting or quota.
// Labels: tenant, kind ("rate" = per-minute limit, "quota" = daily token quota)
var RateLimitHitsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "rate_limit_hits_total",
		Help: "Total requests rejected by rate limiting or daily quota.",
	},
	[]string{"tenant", "kind"},
)
