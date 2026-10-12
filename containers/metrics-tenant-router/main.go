// Command metrics-tenant-router sits between the resident Alloy collector
// and Mimir's write path. Alloy tags each series with one of two hint
// labels: the Kubernetes namespace a cAdvisor/kube-state-metrics sample
// came from, or the exact Traefik "service" label value a Traefik
// router/service metric came from. These are plain (non "__"-prefixed)
// label names -- Prometheus/Alloy drop any label starting with "__" before
// a series reaches remote_write, so a reserved-looking hint label would
// never survive the pipeline. Neither hint is trusted directly:
//
//   - A namespace hint is only honored if it exactly matches a namespace
//     currently present in the authoritative registry served by Cabotage's
//     GET /grafana-integration/tenants endpoint.
//   - A Traefik service hint is only honored via an EXACT match against the
//     registry's own service->namespace map (also supplied by that
//     endpoint). Namespace names are not delimiter-safe substrings of
//     Traefik's generated service labels (e.g. owned namespaces "acme" and
//     "acme-production" can coexist, and a service named "production-web"
//     inside "acme" produces a label indistinguishable from a prefix match
//     against "acme-production"), so prefix/substring guessing is never
//     used -- only an exact, registry-authored mapping.
//
// Unmatched or unverifiable samples are always routed to the fixed infra
// tenant -- ownership is never inferred from an application-controlled
// label. The router fails closed: it performs one synchronous registry
// fetch before accepting any traffic, and on every subsequent refresh
// failure keeps serving the last verified mapping rather than guessing.
//
// remote_write decoding/encoding uses the official Prometheus prompb types
// (which implement their own gogo-proto-generated Marshal/Unmarshal, not
// google.golang.org/protobuf's proto.Message) and the golang/snappy codec
// -- both maintained upstream dependencies, intentionally avoiding
// hand-rolled remote_write wire format parsing.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// reservedIncomingLabels are stripped from every incoming series regardless
// of hint-label configuration: __tenant_id__ (and similar) are sometimes
// used by other Prometheus-ecosystem tooling as a routing hint and must
// never be trusted coming from a scrape target.
var reservedIncomingLabels = []string{"__tenant_id__"}

type config struct {
	listenAddr      string
	mimirWriteURL   string
	tenantsURL      string
	proxyKey        string
	namespaceLabel  string
	serviceLabel    string
	defaultTenant   string
	refreshInterval time.Duration
	requestTimeout  time.Duration
	tlsCertFile     string
	tlsKeyFile      string
	caFile          string
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required env var %s", name)
	}
	return v
}

func envDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// validateFixedURL enforces that a configured upstream/callback URL is a
// plain http(s) URL with a host and nothing else attacker-relevant. Parse
// failures are logged without the raw input: a net/url parse error embeds
// the original string verbatim, which could otherwise leak embedded
// userinfo/query secrets into logs.
func validateFixedURL(name, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid %s: could not be parsed as a URL", name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		log.Fatalf("invalid %s: scheme must be http or https", name)
	}
	if u.Host == "" {
		log.Fatalf("invalid %s: missing host", name)
	}
	if u.User != nil {
		log.Fatalf("invalid %s: must not contain userinfo", name)
	}
	if u.RawQuery != "" {
		log.Fatalf("invalid %s: must not contain a query string", name)
	}
	if u.Fragment != "" {
		log.Fatalf("invalid %s: must not contain a fragment", name)
	}
	return raw
}

func loadConfig() config {
	refresh, err := time.ParseDuration(envDefault("REGISTRY_REFRESH_INTERVAL", "30s"))
	if err != nil {
		log.Fatalf("invalid REGISTRY_REFRESH_INTERVAL: %v", err)
	}
	return config{
		listenAddr:      envDefault("LISTEN_ADDR", "0.0.0.0:8443"),
		mimirWriteURL:   validateFixedURL("MIMIR_WRITE_URL", mustEnv("MIMIR_WRITE_URL")),
		tenantsURL:      validateFixedURL("TENANT_REGISTRY_URL", mustEnv("TENANT_REGISTRY_URL")),
		proxyKey:        mustEnv("TENANT_REGISTRY_KEY"),
		namespaceLabel:  envDefault("TENANT_NAMESPACE_HINT_LABEL", "cabotage_tenant_namespace"),
		serviceLabel:    envDefault("TENANT_SERVICE_HINT_LABEL", "cabotage_tenant_service"),
		defaultTenant:   envDefault("DEFAULT_TENANT", "cabotage-infra"),
		refreshInterval: refresh,
		requestTimeout:  10 * time.Second,
		tlsCertFile:     mustEnv("TLS_CERT_FILE"),
		tlsKeyFile:      mustEnv("TLS_KEY_FILE"),
		caFile:          mustEnv("TLS_CA_FILE"),
	}
}

func newTLSClientConfig(caFile string) *tls.Config {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA bundle: %v", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatalf("no certificates found in CA bundle")
	}
	return &tls.Config{RootCAs: pool}
}

// --- Registry ---

type registryService struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Application string `json:"application"`
	Environment string `json:"environment"`
	Project     string `json:"project"`
}

type registryTenant struct {
	OrganizationID string            `json:"organization_id"`
	TenantID       string            `json:"tenant_id"`
	Namespaces     []string          `json:"namespaces"`
	Services       []registryService `json:"services"`
}

type registryResponse struct {
	Tenants []registryTenant `json:"tenants"`
}

// registrySnapshot holds the last successfully verified ownership data.
// Resolution always uses the namespace itself as the tenant ID (matching
// the existing Loki convention), never the organization UUID.
type registrySnapshot struct {
	namespaces map[string]struct{}
	services   map[string]registryService // exact Traefik "service" label -> owned registry record
}

type registryCache struct {
	mu            sync.RWMutex
	snapshot      registrySnapshot
	everValidated bool
}

func (c *registryCache) replace(s registrySnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = s
	c.everValidated = true
}

// resolveNamespace returns the validated tenant for a cAdvisor/kube-state
// namespace hint: an exact match against the registry's namespace set, or
// the fallback tenant.
func (c *registryCache) resolveNamespace(candidate, fallback string) string {
	if candidate == "" {
		return fallback
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.everValidated {
		return fallback
	}
	if _, ok := c.snapshot.namespaces[candidate]; ok {
		return candidate
	}
	return fallback
}

// resolveServiceFull returns the validated tenant plus the full registry
// record (used to overwrite application/environment/project/namespace
// labels with trusted values instead of whatever an exporter attached) for
// an EXACT match against the registry's service->namespace map. No prefix
// or substring matching is performed.
func (c *registryCache) resolveServiceFull(candidate string) (tenant string, svc registryService, ok bool) {
	if candidate == "" {
		return "", registryService{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.everValidated {
		return "", registryService{}, false
	}
	svc, found := c.snapshot.services[candidate]
	if !found {
		return "", registryService{}, false
	}
	return svc.Namespace, svc, true
}

func fetchRegistry(client *http.Client, cfg config) (registrySnapshot, error) {
	req, err := http.NewRequest(http.MethodGet, cfg.tenantsURL, nil)
	if err != nil {
		return registrySnapshot{}, err
	}
	req.Header.Set("X-Tenant-Registry-Key", cfg.proxyKey)

	resp, err := client.Do(req)
	if err != nil {
		return registrySnapshot{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return registrySnapshot{}, errors.New("unexpected registry status: " + resp.Status)
	}

	var parsed registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return registrySnapshot{}, err
	}

	snap := registrySnapshot{
		namespaces: make(map[string]struct{}),
		services:   make(map[string]registryService),
	}
	ambiguous := make(map[string]struct{})
	for _, t := range parsed.Tenants {
		for _, ns := range t.Namespaces {
			if ns != "" {
				snap.namespaces[ns] = struct{}{}
			}
		}
		for _, svc := range t.Services {
			if svc.Name == "" || svc.Namespace == "" {
				continue
			}
			if existing, ok := snap.services[svc.Name]; ok && existing.Namespace != svc.Namespace {
				// A service name that maps to more than one namespace is
				// unresolvable by exact match; never guess, exclude it so
				// it falls back to the default (infra) tenant.
				ambiguous[svc.Name] = struct{}{}
				continue
			}
			snap.services[svc.Name] = svc
		}
	}
	for name := range ambiguous {
		delete(snap.services, name)
	}
	return snap, nil
}

func refreshLoop(cache *registryCache, client *http.Client, cfg config) {
	tick := time.NewTicker(cfg.refreshInterval)
	defer tick.Stop()
	for range tick.C {
		snap, err := fetchRegistry(client, cfg)
		if err != nil {
			log.Printf("registry refresh failed, keeping last verified mapping: %v", err)
			continue
		}
		cache.replace(snap)
	}
}

// --- remote_write handling ---

func labelValue(ls []prompb.Label, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}

// stripLabels removes labels by name, in place (no new backing array).
func stripLabels(ls []prompb.Label, names ...string) []prompb.Label {
	out := ls[:0]
	for _, l := range ls {
		drop := false
		for _, n := range names {
			if l.Name == n {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, l)
		}
	}
	return out
}

// setLabel overwrites the value of an existing label or appends it if
// absent. Used to force trusted registry metadata onto a series rather
// than keep whatever an upstream exporter may have attached.
func setLabel(ls []prompb.Label, name, value string) []prompb.Label {
	for i := range ls {
		if ls[i].Name == name {
			ls[i].Value = value
			return ls
		}
	}
	return append(ls, prompb.Label{Name: name, Value: value})
}

// sortLabels orders labels by name, as required by Prometheus/Mimir's
// remote_write and storage layer whenever a series' label set is mutated
// after the original (already-sorted) scrape output.
func sortLabels(ls []prompb.Label) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].Name < ls[j].Name })
}

func splitByTenant(wr *prompb.WriteRequest, cache *registryCache, cfg config) map[string]*prompb.WriteRequest {
	groups := make(map[string]*prompb.WriteRequest)
	for _, ts := range wr.Timeseries {
		ts.Labels = stripLabels(ts.Labels, reservedIncomingLabels...)

		nsCandidate := labelValue(ts.Labels, cfg.namespaceLabel)
		svcCandidate := labelValue(ts.Labels, cfg.serviceLabel)

		tenant := cfg.defaultTenant
		mutated := false
		switch {
		case nsCandidate != "":
			tenant = cache.resolveNamespace(nsCandidate, cfg.defaultTenant)
		case svcCandidate != "":
			var svc registryService
			var ok bool
			tenant, svc, ok = cache.resolveServiceFull(svcCandidate)
			if !ok {
				tenant = cfg.defaultTenant
			} else {
				// Trusted, registry-authored metadata only -- never trust
				// whatever label (if any) an exporter already attached
				// (e.g. Traefik's own pod "environment" label, which
				// describes Traefik itself, not the routed application).
				ts.Labels = setLabel(ts.Labels, "namespace", svc.Namespace)
				ts.Labels = setLabel(ts.Labels, "application", svc.Application)
				ts.Labels = setLabel(ts.Labels, "environment", svc.Environment)
				ts.Labels = setLabel(ts.Labels, "project", svc.Project)
				mutated = true
			}
		}

		ts.Labels = stripLabels(ts.Labels, cfg.namespaceLabel, cfg.serviceLabel)
		if mutated {
			sortLabels(ts.Labels)
		}

		g, ok := groups[tenant]
		if !ok {
			g = &prompb.WriteRequest{}
			groups[tenant] = g
		}
		g.Timeseries = append(g.Timeseries, ts)
	}

	// Metric metadata (type/help/unit per metric family name) is global to
	// the whole write request, not scoped to any series' labels. Copying
	// it verbatim onto every tenant group would expose the family names of
	// infra-only metrics (e.g. ones never resolved to a customer tenant)
	// to every customer tenant. Instead, include only the metadata entries
	// whose MetricFamilyName matches a "__name__" value actually present
	// among that group's own timeseries.
	for _, g := range groups {
		families := make(map[string]struct{}, len(g.Timeseries))
		for _, ts := range g.Timeseries {
			if name := labelValue(ts.Labels, "__name__"); name != "" {
				families[name] = struct{}{}
			}
		}
		for _, m := range wr.Metadata {
			if _, ok := families[m.MetricFamilyName]; ok {
				g.Metadata = append(g.Metadata, m)
			}
		}
	}
	return groups
}

func forwardTenant(client *http.Client, cfg config, tenant string, wr *prompb.WriteRequest) error {
	// prompb types are gogo-proto generated: they implement Marshal/
	// Unmarshal directly, not google.golang.org/protobuf's proto.Message.
	payload, err := wr.Marshal()
	if err != nil {
		return err
	}
	compressed := snappy.Encode(nil, payload)

	req, err := http.NewRequest(http.MethodPost, cfg.mimirWriteURL, bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	req.Header.Set("X-Scope-Orgid", tenant)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return errors.New("mimir write rejected: " + resp.Status)
	}
	return nil
}

func handlePush(cache *registryCache, upstream *http.Client, cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "snappy" {
			http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		decoded, err := snappy.Decode(nil, body)
		if err != nil {
			http.Error(w, "snappy decode error", http.StatusBadRequest)
			return
		}
		var wr prompb.WriteRequest
		if err := wr.Unmarshal(decoded); err != nil {
			http.Error(w, "protobuf decode error", http.StatusBadRequest)
			return
		}

		groups := splitByTenant(&wr, cache, cfg)
		var failed []string
		for tenant, g := range groups {
			if err := forwardTenant(upstream, cfg, tenant, g); err != nil {
				log.Printf("forward to tenant %q failed: %v", tenant, err)
				failed = append(failed, tenant)
			}
		}
		if len(failed) > 0 {
			http.Error(w, "upstream write failed for tenants: "+strings.Join(failed, ","), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// noRedirect prevents an HTTP client from following redirects, so a
// redirect response from a misbehaving/compromised upstream can never
// cause TENANT_REGISTRY_KEY (on the registry client) to be resent to an
// arbitrary Location.
func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func main() {
	cfg := loadConfig()
	tlsClientCfg := newTLSClientConfig(cfg.caFile)

	registryClient := &http.Client{
		Timeout:       cfg.requestTimeout,
		Transport:     &http.Transport{TLSClientConfig: tlsClientCfg},
		CheckRedirect: noRedirect,
	}

	cache := &registryCache{snapshot: registrySnapshot{
		namespaces: map[string]struct{}{},
		services:   map[string]registryService{},
	}}

	// Perform exactly one synchronous registry fetch before accepting any
	// traffic. On success, the cache is seeded with real ownership data.
	// On failure, log and proceed anyway with the cache's zero-value empty,
	// unvalidated snapshot -- every sample routes to the fixed infra
	// tenant until the periodic refreshLoop below completes a successful
	// fetch. This fails closed without blocking collector availability
	// indefinitely on registry downtime.
	if snap, err := fetchRegistry(registryClient, cfg); err != nil {
		log.Printf("initial registry fetch failed, starting fail-closed (infra-only) until next refresh: %v", err)
	} else {
		cache.replace(snap)
	}
	go refreshLoop(cache, registryClient, cfg)

	upstreamClient := &http.Client{
		Timeout:       cfg.requestTimeout,
		Transport:     &http.Transport{TLSClientConfig: tlsClientCfg},
		CheckRedirect: noRedirect,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /push", handlePush(cache, upstreamClient, cfg))

	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("metrics-tenant-router listening on %s", cfg.listenAddr)
	if err := server.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
