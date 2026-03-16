# Cabotage Containers

Container images for [Cabotage](https://github.com/cabotage/cabotage-app), a platform for deploying and managing applications on Kubernetes with Vault and Consul integration.

## Containers

### base

Base Python image used by other containers. Sets up a Python 3.13 virtual environment with common dependencies.

### sidecar

A sidecar container that handles Vault and Consul secret lifecycle for pods:

- Authenticates to Vault using Kubernetes service account tokens
- Fetches and writes TLS certificates from Vault PKI
- Fetches Consul ACL tokens via Vault
- Continuously renews Vault tokens, leases, and certificates before expiry

Uses [ghostunnel](https://github.com/ghostunnel/ghostunnel) for TLS tunneling.

### enrollment-operator

A Kubernetes operator (built with [kopf](https://github.com/nolar/kopf)) that watches `CabotageEnrollment` custom resources and provisions:

- Vault policies and Kubernetes auth roles
- Vault PKI roles for TLS certificate issuance
- Consul ACL policies and Vault Consul secret backend roles

Supports policy inheritance between enrollments via `inheritsFrom`.

### cabotage-ca-admission

A mutating admission webhook that injects the `cabotage-ca` ConfigMap as a projected volume into all pods, making the Cabotage CA certificate available at `/var/run/secrets/cabotage.io`.

### registry

A Docker registry (based on `registry:2.8.3`) with a custom entrypoint that installs the Cabotage CA certificate into the system trust store.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
