// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

package tracer

import (
	"encoding/json"
	"io"
	"math"
	"path"
	"regexp"
	"sync"
	"time"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"

	"golang.org/x/time/rate"
)

// Sampler is the generic interface of any sampler. It must be safe for concurrent use.
type Sampler interface {
	// Sample returns true if the given span should be sampled.
	Sample(span Span) bool
}

// RateSampler is a sampler implementation which randomly selects spans using a
// provided rate. For example, a rate of 0.75 will permit 75% of the spans.
// RateSampler implementations should be safe for concurrent use.
type RateSampler interface {
	Sampler

	// Rate returns the current sample rate.
	Rate() float64

	// SetRate sets a new sample rate.
	SetRate(rate float64)
}

// rateSampler samples from a sample rate.
type rateSampler struct {
	sync.RWMutex
	rate float64
}

// NewAllSampler is a short-hand for NewRateSampler(1). It is all-permissive.
func NewAllSampler() RateSampler { return NewRateSampler(1) }

// NewRateSampler returns an initialized RateSampler with a given sample rate.
func NewRateSampler(rate float64) RateSampler {
	return &rateSampler{rate: rate}
}

// Rate returns the current rate of the sampler.
func (r *rateSampler) Rate() float64 {
	r.RLock()
	defer r.RUnlock()
	return r.rate
}

// SetRate sets a new sampling rate.
func (r *rateSampler) SetRate(rate float64) {
	r.Lock()
	r.rate = rate
	r.Unlock()
}

// constants used for the Knuth hashing, same as agent.
const knuthFactor = uint64(1111111111111111111)

// Sample returns true if the given span should be sampled.
func (r *rateSampler) Sample(spn ddtrace.Span) bool {
	if r.rate == 1 {
		// fast path
		return true
	}
	s, ok := spn.(*span)
	if !ok {
		return false
	}
	r.RLock()
	defer r.RUnlock()
	return sampledByRate(s.TraceID, r.rate)
}

// sampledByRate verifies if the number n should be sampled at the specified
// rate.
func sampledByRate(n uint64, rate float64) bool {
	if rate < 1 {
		return n*knuthFactor < uint64(rate*math.MaxUint64)
	}
	return true
}

// prioritySampler holds a set of per-service sampling rates and applies
// them to spans.
type prioritySampler struct {
	mu          sync.RWMutex
	rates       map[string]float64
	defaultRate float64
}

func newPrioritySampler() *prioritySampler {
	return &prioritySampler{
		rates:       make(map[string]float64),
		defaultRate: 1.,
	}
}

// readRatesJSON will try to read the rates as JSON from the given io.ReadCloser.
func (ps *prioritySampler) readRatesJSON(rc io.ReadCloser) error {
	var payload struct {
		Rates map[string]float64 `json:"rate_by_service"`
	}
	if err := json.NewDecoder(rc).Decode(&payload); err != nil {
		return err
	}
	rc.Close()
	const defaultRateKey = "service:,env:"
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.rates = payload.Rates
	if v, ok := ps.rates[defaultRateKey]; ok {
		ps.defaultRate = v
		delete(ps.rates, defaultRateKey)
	}
	return nil
}

// getRate returns the sampling rate to be used for the given span. Callers must
// guard the span.
func (ps *prioritySampler) getRate(spn *span) float64 {
	key := "service:" + spn.Service + ",env:" + spn.Meta[ext.Environment]
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if rate, ok := ps.rates[key]; ok {
		return rate
	}
	return ps.defaultRate
}

// apply applies sampling priority to the given span. Caller must ensure it is safe
// to modify the span.
func (ps *prioritySampler) apply(spn *span) {
	rate := ps.getRate(spn)
	if sampledByRate(spn.TraceID, rate) {
		spn.SetTag(ext.SamplingPriority, ext.PriorityAutoKeep)
	} else {
		spn.SetTag(ext.SamplingPriority, ext.PriorityAutoReject)
	}
	spn.SetTag(keySamplingPriorityRate, rate)
}

type spanDataSampler struct {
	rules   []Rule
	limiter *rate.Limiter
	// "effective rate" calculations
	mu sync.Mutex
	ts int64
	n  int
	t  int
	pr float64
}

func newSpanDataSampler(rules []Rule, sampleRate float64) Sampler {
	burst := int(math.Floor(sampleRate))
	if burst < 1 {
		burst = 1
	}
	return &spanDataSampler{
		rules:   rules,
		limiter: rate.NewLimiter(rate.Limit(sampleRate), burst),
	}
}

func (sds *spanDataSampler) Sample(s Span) bool {
	spn, ok := s.(*span)
	if !ok {
		return false
	}
	matched := false
	sr := 0.0
	for _, v := range sds.rules {
		if v.match(spn) {
			matched = true
			sr = v.Rate
			break
		}
	}
	if !matched {
		return false
	}
	// rate sample
	s.SetTag("_dd.rule_psr", sr)
	if !sampledByRate(spn.TraceID, sr) {
		spn.SetTag(ext.SamplingPriority, ext.PriorityAutoReject)
		return false
	}
	// global rate limit and effective rate calculations
	defer sds.mu.Unlock()
	sds.mu.Lock()
	if ts := time.Now().Unix(); ts > sds.ts {
		// update "previous rate" and reset
		if ts-sds.ts == 1 && sds.t > 0 && sds.n > 0 {
			sds.pr = float64(sds.n) / float64(sds.t)
		} else {
			sds.pr = 0.0
		}
		sds.ts = ts
		sds.n = 0
		sds.t = 0
	}

	sds.t += 1
	if !sds.limiter.Allow() {
		spn.SetTag(ext.SamplingPriority, ext.PriorityAutoReject)
		return false
	}
	spn.SetTag(ext.SamplingPriority, ext.PriorityAutoKeep)
	sds.n += 1
	// calculate effective rate
	er := (sds.pr + (float64(sds.n) / float64(sds.t))) / 2.0
	// tag span with rates and return true
	spn.SetTag("_dd.limit_psr", er)

	return true
}

type ValueMatcher func(string) bool

type Rule struct {
	Service ValueMatcher
	Name    ValueMatcher
	Tags    map[string]ValueMatcher
	Rate    float64
}

func ValueEquals(s string) ValueMatcher {
	return func(val string) bool {
		return val == s
	}
}

func ValueMatchesRegex(r string) ValueMatcher {
	re, err := regexp.Compile(r)
	if err != nil {
		// log an error
		return func(string) bool {
			return false
		}
	}
	return func(val string) bool {
		return re.FindStringIndex(val) != nil
	}
}

func ValueMatchesGlob(g string) ValueMatcher {
	return func(val string) bool {
		m, _ := path.Match(g, val)
		return m
	}
}

func (r *Rule) match(s *span) bool {
	if r.Service != nil && !r.Service(s.Service) {
		return false
	}
	if r.Name != nil && !r.Name(s.Name) {
		return false
	}
	for k, v := range r.Tags {
		if !v(s.Meta[k]) {
			return false
		}
	}
	return true
}
