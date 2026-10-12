# metrics-tenant-router

Registry-aware Prometheus remote_write tenant splitter. Decodes each
`prompb.WriteRequest` using the official `prometheus/prometheus/prompb`
types and `golang/snappy` (both maintained upstream dependencies -- no
hand-rolled remote_write protocol parsing), resolves a per-series tenant
against a periodically-refreshed copy of the authoritative
`/grafana-integration/tenants` registry, strips the hint label, groups
series by resolved tenant, and re-issues one remote_write request per
tenant upstream to Mimir with `X-Scope-OrgID` set.

`go.sum` is checked in (generated via `go mod tidy`); the Dockerfile uses
`go mod download` against the pinned checksums rather than resolving them
at build time.

Deployed by the Cabotage Terraform module
(`monitoring_tenant_routing_enabled`) and the PSF `org-monitoring`
Kustomize component.
