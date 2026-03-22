use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use rand::Rng as _;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// --- Vault API helpers ---

fn vault_client(vault_ca_file: &str) -> Result<Client> {
    let ca_pem = fs::read(vault_ca_file)
        .with_context(|| format!("reading CA file {vault_ca_file}"))?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)?;
    Ok(Client::builder()
        .add_root_certificate(ca_cert)
        .build()?)
}

fn wrapping_token_lookup(client: &Client, vault_addr: &str, token: &str) -> Result<Value> {
    let resp = client
        .post(format!("{vault_addr}/v1/sys/wrapping/lookup"))
        .json(&json!({ "token": token }))
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

fn unwrap_vault_response(client: &Client, vault_addr: &str, wrapping_token: &str) -> Result<Value> {
    let resp = client
        .post(format!("{vault_addr}/v1/sys/wrapping/unwrap"))
        .header("X-Vault-Token", wrapping_token)
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

fn token_lookup_self(client: &Client, vault_addr: &str, token: &str) -> Result<Value> {
    let resp = client
        .get(format!("{vault_addr}/v1/auth/token/lookup-self"))
        .header("X-Vault-Token", token)
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

fn token_renew_self(client: &Client, vault_addr: &str, token: &str) -> Result<()> {
    client
        .post(format!("{vault_addr}/v1/auth/token/renew-self"))
        .header("X-Vault-Token", token)
        .json(&json!({}))
        .send()?
        .error_for_status()?;
    Ok(())
}

fn token_revoke_self(client: &Client, vault_addr: &str, token: &str) -> Result<()> {
    client
        .post(format!("{vault_addr}/v1/auth/token/revoke-self"))
        .header("X-Vault-Token", token)
        .json(&json!({}))
        .send()?
        .error_for_status()?;
    Ok(())
}

fn leases_lookup(client: &Client, vault_addr: &str, token: &str, lease_id: &str) -> Result<Value> {
    let resp = client
        .put(format!("{vault_addr}/v1/sys/leases/lookup"))
        .header("X-Vault-Token", token)
        .json(&json!({ "lease_id": lease_id }))
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

fn leases_renew(client: &Client, vault_addr: &str, token: &str, lease_id: &str) -> Result<Value> {
    let resp = client
        .put(format!("{vault_addr}/v1/sys/leases/renew"))
        .header("X-Vault-Token", token)
        .json(&json!({ "lease_id": lease_id }))
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

fn vault_auth_kubernetes_login(
    client: &Client,
    vault_addr: &str,
    vault_backend: &str,
    vault_role: &str,
    jwt: &str,
    wrap: bool,
    unwrap: bool,
) -> Result<Value> {
    let mut builder = client
        .post(format!("{vault_addr}/v1/{vault_backend}"))
        .json(&json!({ "jwt": jwt, "role": vault_role }));
    if wrap {
        builder = builder.header("X-Vault-Wrap-TTL", "60s");
    }
    let resp = builder.send()?.error_for_status()?;
    let mut token: Value = resp.json()?;

    if wrap {
        let accessor = token["wrap_info"]["accessor"].as_str().unwrap_or("");
        eprintln!("fetched wrapped token with accessor {accessor}");
        if unwrap {
            eprintln!("unwrapping accessor {accessor}");
            let wrapping_token = token["wrap_info"]["token"]
                .as_str()
                .context("missing wrap_info.token")?
                .to_string();
            token = unwrap_vault_response(client, vault_addr, &wrapping_token)?;
            let accessor = token["auth"]["accessor"].as_str().unwrap_or("");
            eprintln!("fetched unwrapped token with accessor {accessor}");
        }
    } else {
        let accessor = token["auth"]["accessor"].as_str().unwrap_or("");
        eprintln!("fetched token with accessor {accessor}");
    }
    Ok(token)
}

// --- DNS helpers ---

fn service_dns(service_name: &str, namespace: &str, domain: &str) -> Vec<String> {
    vec![
        format!("{service_name}.{namespace}.svc.{domain}"),
        format!("{service_name}.{namespace}.svc"),
        format!("{service_name}.{namespace}"),
        service_name.to_string(),
    ]
}

fn pod_dns(pod_ip: &str, namespace: &str, domain: &str) -> Vec<String> {
    let ip_dashed = pod_ip.replace('.', "-");
    vec![
        format!("{ip_dashed}.{namespace}.pod.{domain}"),
        format!("{ip_dashed}.{namespace}.pod"),
    ]
}

fn headless_dns(hostname: &str, subdomain: &str, namespace: &str, domain: &str) -> Vec<String> {
    vec![
        format!("{hostname}.{subdomain}.{namespace}.svc.{domain}"),
        format!("{hostname}.{subdomain}.{namespace}.svc"),
        format!("{hostname}.{subdomain}.{namespace}"),
        format!("{hostname}.{subdomain}"),
        hostname.to_string(),
    ]
}

// --- Certificate helpers ---

fn request_vault_certificate(
    client: &Client,
    vault_addr: &str,
    vault_token: &str,
    vault_ca_file: &str,
    vault_pki_backend: &str,
    vault_pki_role: &str,
    common_name: &str,
    alt_names: &[String],
    ip_sans: &[String],
) -> Result<Value> {
    let _ = vault_ca_file; // already baked into the client
    let resp = client
        .post(format!("{vault_addr}/v1/{vault_pki_backend}/issue/{vault_pki_role}"))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "common_name": common_name,
            "alt_names": alt_names.join(","),
            "ip_sans": ip_sans.join(","),
        }))
        .send()?
        .error_for_status()?;
    let body: Value = resp.json()?;
    eprintln!(
        "Obtained Private Key ({}) and Certificate with:",
        body["data"]["private_key_type"].as_str().unwrap_or("")
    );
    eprintln!(
        "  - Serial Number: {}",
        body["data"]["serial_number"].as_str().unwrap_or("")
    );
    eprintln!("  - Vault Accessor: {}", body["accessor"].as_str().unwrap_or(""));
    eprintln!("  - Vault Lease ID: {}", body["lease_id"].as_str().unwrap_or(""));
    eprintln!("  - Vault Lease Duration: {}", body["lease_duration"]);
    Ok(body)
}

fn write_key_material(cert_dir: &Path, cert_object: &Value) -> Result<()> {
    let data = &cert_object["data"];
    let private_key = data["private_key"].as_str().context("missing private_key")?;
    let certificate = data["certificate"].as_str().context("missing certificate")?;
    let issuing_ca = data["issuing_ca"].as_str().context("missing issuing_ca")?;

    fs::write(cert_dir.join("key.pem"), format!("{private_key}\n"))?;
    fs::write(cert_dir.join("cert.pem"), format!("{certificate}\n"))?;
    fs::write(
        cert_dir.join("combined.pem"),
        format!("{certificate}\n{issuing_ca}\n{private_key}\n"),
    )?;
    fs::write(cert_dir.join("ca.pem"), format!("{issuing_ca}\n"))?;
    fs::write(
        cert_dir.join("chain.pem"),
        format!("{certificate}\n{issuing_ca}\n"),
    )?;
    eprintln!(
        "Wrote Key Material to {}",
        cert_dir.join("{cert.pem, key.pem, ca.pem, chain.pem}").display()
    );
    Ok(())
}

fn certificate_needs_renewed(cert_dir: &Path) -> Result<bool> {
    let pem_data = fs::read(cert_dir.join("cert.pem"))?;
    let pem_block = pem::parse(&pem_data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_block.contents())?;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let now = Utc::now().timestamp();
    let lifetime = not_after - not_before;
    Ok((not_after - now) < lifetime / 2)
}

fn read_cert(cert_dir: &Path) -> Result<(String, Vec<String>, Vec<String>)> {
    let pem_data = fs::read(cert_dir.join("cert.pem"))?;
    let pem_block = pem::parse(&pem_data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_block.contents())?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .context("no CN in certificate")?
        .to_string();

    let mut dns_names = Vec::new();
    let mut ip_sans = Vec::new();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => {
                    dns_names.push(dns.to_string());
                }
                x509_parser::extensions::GeneralName::IPAddress(ip_bytes) => {
                    let ip_str = if ip_bytes.len() == 4 {
                        format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
                    } else {
                        // IPv6 - format as hex
                        ip_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    };
                    ip_sans.push(ip_str);
                }
                _ => {}
            }
        }
    }

    Ok((common_name, dns_names, ip_sans))
}

fn vault_fetch_certificate(
    client: &Client,
    vault_addr: &str,
    vault_token: &str,
    vault_ca_file: &str,
    vault_pki_backend: &str,
    vault_pki_role: &str,
    cert_dir: &Path,
    from_cert: bool,
    hostname: &str,
    subdomain: &str,
    namespace: &str,
    cluster_domain: &str,
    pod_ip: &str,
    additional_dns_names: &str,
    service_names: &str,
    service_ips: &str,
) -> Result<()> {
    let (common_name, dns_names, ip_sans) = if from_cert {
        read_cert(cert_dir)?
    } else {
        let mut dns = pod_dns(pod_ip, namespace, cluster_domain);
        dns.extend(additional_dns_names.split(',').filter(|s| !s.is_empty()).map(String::from));
        for svc in service_names.split(',').filter(|s| !s.is_empty()) {
            dns.extend(service_dns(svc, namespace, cluster_domain));
        }
        if !hostname.is_empty() && !subdomain.is_empty() {
            dns.extend(headless_dns(hostname, subdomain, namespace, cluster_domain));
        }
        let mut ips = vec![pod_ip.to_string()];
        ips.extend(service_ips.split(',').filter(|s| !s.is_empty()).map(String::from));
        let cn = dns[0].clone();
        (cn, dns, ips)
    };

    let cert_response = request_vault_certificate(
        client,
        vault_addr,
        vault_token,
        vault_ca_file,
        vault_pki_backend,
        vault_pki_role,
        &common_name,
        &dns_names,
        &ip_sans,
    )?;
    write_key_material(cert_dir, &cert_response)?;
    Ok(())
}

// --- Consul token ---

fn request_consul_token(
    client: &Client,
    vault_addr: &str,
    token: &str,
    consul_backend: &str,
    consul_role: &str,
) -> Result<Value> {
    let resp = client
        .get(format!("{vault_addr}/v1/{consul_backend}/creds/{consul_role}"))
        .header("X-Vault-Token", token)
        .send()?
        .error_for_status()?;
    let body: Value = resp.json()?;
    eprintln!("Obtained Consul Token with:");
    eprintln!("  - Vault Lease ID: {}", body["lease_id"].as_str().unwrap_or(""));
    eprintln!(
        "  - Vault Lease Duration: {}",
        body["lease_duration"]
    );
    Ok(body)
}

fn write_consul_token(consul_secrets_path: &Path, consul_token_object: &Value) -> Result<()> {
    let lease_id = consul_token_object["lease_id"]
        .as_str()
        .context("missing lease_id")?;
    let token = consul_token_object["data"]["token"]
        .as_str()
        .context("missing data.token")?;
    let lease_sha = hex::encode(Sha256::digest(lease_id.as_bytes()));

    fs::write(consul_secrets_path.join("leases").join(&lease_sha), lease_id)?;
    fs::write(consul_secrets_path.join("consul-token"), token)?;
    eprintln!(
        "Wrote Consul Token to {}",
        consul_secrets_path.join("consul-token").display()
    );
    Ok(())
}

fn vault_fetch_consul_token(
    client: &Client,
    vault_addr: &str,
    token_contents: &str,
    vault_consul_backend: &str,
    vault_consul_role: &str,
    consul_secrets_path: &Path,
) -> Result<()> {
    let resp = request_consul_token(
        client,
        vault_addr,
        token_contents,
        vault_consul_backend,
        vault_consul_role,
    )?;
    write_consul_token(consul_secrets_path, &resp)?;
    Ok(())
}

// --- Shared command logic ---

#[allow(clippy::too_many_arguments)]
fn do_kube_login(
    client: &Client,
    vault_addr: &str,
    vault_ca_file: &str,
    vault_secrets_path: &str,
    vault_auth_kubernetes_role: Option<&str>,
    vault_auth_kubernetes_backend: &str,
    fetch_consul_token: bool,
    consul_secrets_path: &str,
    vault_consul_role: Option<&str>,
    vault_consul_backend: &str,
    fetch_cert: bool,
    cert_dir: &str,
    vault_pki_backend: &str,
    vault_pki_role: Option<&str>,
    hostname: &str,
    subdomain: &str,
    cluster_domain: &str,
    namespace: &str,
    _pod_name: Option<&str>,
    pod_ip: Option<&str>,
    additional_dns_names: &str,
    service_names: &str,
    service_ips: &str,
    wrap: bool,
    unwrap: bool,
) -> Result<Option<String>> {
    if fetch_consul_token && vault_consul_role.is_none() {
        bail!("--vault-consul-role is required when fetching consul token");
    }
    if fetch_cert {
        if vault_pki_role.is_none() {
            bail!("--vault-pki-role is required when fetching TLS certificate");
        }
        if pod_ip.is_none() {
            bail!("--pod-ip is required when fetching TLS certificate");
        }
    }
    if (fetch_cert || fetch_consul_token) && !unwrap {
        bail!(
            "--no-unwrap cannot be used with --fetch-consul-token or --fetch-cert!\n\
             unwrapped token must be accessible during bootstrap"
        );
    }

    let vault_secrets = Path::new(vault_secrets_path);
    fs::create_dir_all(vault_secrets.join("leases"))?;

    let jwt = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
        .context("reading kubernetes service account token")?;

    let mut token_contents: Option<String> = None;

    if let Some(role) = vault_auth_kubernetes_role {
        eprintln!("Attempting Vault Auth Login with Kubernetes for {role}");
        eprintln!("reading jwt for vault kubernetes auth");
        eprintln!("fetching vault token");
        let token = vault_auth_kubernetes_login(
            client,
            vault_addr,
            vault_auth_kubernetes_backend,
            role,
            &jwt,
            wrap,
            unwrap,
        )?;
        let (token_type, token_path, contents) = if (wrap && unwrap) || !wrap {
            (
                "vault-token",
                vault_secrets.join("vault-token"),
                token["auth"]["client_token"]
                    .as_str()
                    .context("missing auth.client_token")?
                    .to_string(),
            )
        } else {
            (
                "wrapped-vault-token",
                vault_secrets.join("wrapped-vault-token"),
                token["wrap_info"]["token"]
                    .as_str()
                    .context("missing wrap_info.token")?
                    .to_string(),
            )
        };
        eprintln!("writing {token_type} to {}", token_path.display());
        fs::write(&token_path, &contents)?;
        token_contents = Some(contents);
    }

    if fetch_consul_token {
        let consul_path = Path::new(consul_secrets_path);
        fs::create_dir_all(consul_path.join("leases"))?;
        vault_fetch_consul_token(
            client,
            vault_addr,
            token_contents.as_deref().context("no vault token available")?,
            vault_consul_backend,
            vault_consul_role.unwrap(),
            consul_path,
        )?;
    }

    if fetch_cert {
        let cert_path = Path::new(cert_dir);
        fs::create_dir_all(cert_path.join("leases"))?;
        vault_fetch_certificate(
            client,
            vault_addr,
            token_contents.as_deref().context("no vault token available")?,
            vault_ca_file,
            vault_pki_backend,
            vault_pki_role.unwrap(),
            cert_path,
            false,
            hostname,
            subdomain,
            namespace,
            cluster_domain,
            pod_ip.unwrap(),
            additional_dns_names,
            service_names,
            service_ips,
        )?;
    }

    Ok(token_contents)
}

#[allow(clippy::too_many_arguments)]
fn do_maintain_loop(
    client: &Client,
    vault_token: &str,
    vault_addr: &str,
    vault_ca_file: &str,
    vault_secrets_path: &str,
    consul_secrets_path: &str,
    cert_dir: &str,
    vault_pki_backend: &str,
    vault_pki_role: Option<&str>,
) -> Result<()> {
    let _ = vault_pki_role; // used via vault_pki_backend prefix matching
    let vault_token_info = token_lookup_self(client, vault_addr, vault_token)?;
    let accessor = vault_token_info["data"]["accessor"].as_str().unwrap_or("");
    let policies: Vec<&str> = vault_token_info["data"]["policies"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    eprintln!("Using token with accessor {accessor} and policies {}", policies.join(", "));

    loop {
        let min_sleep: i64 = 60;
        let max_sleep: i64 = 1800;
        let vault_token_info = token_lookup_self(client, vault_addr, vault_token)?;
        let data = &vault_token_info["data"];
        let accessor = data["accessor"].as_str().unwrap_or("");
        eprintln!("checking vault token with accessor {accessor}");

        let mut sleep_secs = min_sleep;
        if data["renewable"].as_bool().unwrap_or(false) {
            let ttl = data["ttl"].as_i64().unwrap_or(0);
            let creation_ttl = data["creation_ttl"].as_i64().unwrap_or(0);
            if ttl < creation_ttl / 2 {
                eprintln!("renewing vault token with accessor {accessor}");
                token_renew_self(client, vault_addr, vault_token)?;
                sleep_secs = min_sleep;
            } else {
                sleep_secs = (ttl / 4).max(min_sleep).min(max_sleep)
                    - rand::random_range(0..120);
            }
        }

        let lease_dirs: HashSet<PathBuf> = [vault_secrets_path, consul_secrets_path, cert_dir]
            .iter()
            .map(|p| Path::new(p).join("leases"))
            .collect();

        for lease_dir in &lease_dirs {
            eprintln!("Checking expiry of leases in {}...", lease_dir.display());
            let entries = match fs::read_dir(lease_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let lease_file_name = entry.file_name().to_string_lossy().to_string();
                eprintln!("Checking expiry of lease: {lease_file_name}...");
                let lease_id = fs::read_to_string(entry.path())?;
                let lease_resp = leases_lookup(client, vault_addr, vault_token, &lease_id)?;
                let lease_info = &lease_resp["data"];

                if lease_info["id"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with(&format!("{vault_pki_backend}/issue"))
                {
                    continue;
                }

                let ttl = lease_info["ttl"].as_i64().unwrap_or(0);
                if ttl > 0 {
                    let expire_time = lease_info["expire_time"]
                        .as_str()
                        .and_then(|s| s.parse::<DateTime<Utc>>().ok());
                    let issue_time = lease_info["issue_time"]
                        .as_str()
                        .and_then(|s| s.parse::<DateTime<Utc>>().ok());

                    if let (Some(expire), Some(issue)) = (expire_time, issue_time) {
                        let initial_ttl = (expire - issue).num_seconds();
                        if ttl < initial_ttl / 2 {
                            eprintln!("Renewing lease {}...", lease_info["id"]);
                            let new_lease =
                                leases_renew(client, vault_addr, vault_token, &lease_id)?;
                            let new_lease_id =
                                new_lease["lease_id"].as_str().unwrap_or("");
                            let new_duration = &new_lease["lease_duration"];
                            eprintln!("Renewed lease {new_lease_id} for {new_duration}s!");

                            let new_sha = hex::encode(Sha256::digest(new_lease_id.as_bytes()));
                            if new_sha != lease_file_name {
                                fs::remove_file(entry.path())?;
                                fs::write(lease_dir.join(&new_sha), new_lease_id)?;
                            } else {
                                // touch the file
                                let now = filetime::FileTime::now();
                                filetime::set_file_mtime(entry.path(), now)?;
                            }
                        }
                    }
                } else {
                    eprintln!("Removing expired lease file for {}", lease_info["id"]);
                    fs::remove_file(entry.path())?;
                }
            }
        }

        let cert_path = Path::new(cert_dir).join("cert.pem");
        if cert_path.exists() {
            if certificate_needs_renewed(Path::new(cert_dir))? {
                vault_fetch_certificate(
                    client,
                    vault_addr,
                    vault_token,
                    vault_ca_file,
                    vault_pki_backend,
                    vault_pki_role.unwrap_or(""),
                    Path::new(cert_dir),
                    true,  // from_cert
                    "", "", "", "", "", "", "", "",
                )?;
            }
        }

        eprintln!("sleeping {sleep_secs} seconds...");
        thread::sleep(Duration::from_secs(sleep_secs.max(1) as u64));
    }
}

// --- CLI ---

#[derive(Parser)]
#[command(name = "sidecar")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    KubeLogin(KubeLoginArgs),
    Maintain(MaintainArgs),
    KubeLoginAndMaintain(KubeLoginAndMaintainArgs),
}

#[derive(Parser)]
struct KubeLoginArgs {
    #[arg(long, default_value = "default")]
    namespace: String,
    #[arg(long, default_value = "https://vault.cabotage.svc.cluster.local")]
    vault_addr: String,
    #[arg(long, default_value = "/var/run/secrets/cabotage.io/ca.crt")]
    vault_ca_file: String,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    vault_secrets_path: String,
    #[arg(long)]
    vault_auth_kubernetes_role: Option<String>,
    #[arg(long, default_value = "auth/kubernetes/login")]
    vault_auth_kubernetes_backend: String,
    #[arg(long, default_value_t = false)]
    fetch_consul_token: bool,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    consul_secrets_path: String,
    #[arg(long)]
    vault_consul_role: Option<String>,
    #[arg(long, default_value = "cabotage-consul")]
    vault_consul_backend: String,
    #[arg(long, default_value_t = false)]
    fetch_cert: bool,
    #[arg(long, default_value = "/var/run/secrets/vault")]
    cert_dir: String,
    #[arg(long, default_value = "cabotage-ca")]
    vault_pki_backend: String,
    #[arg(long)]
    vault_pki_role: Option<String>,
    #[arg(long, default_value = "")]
    hostname: String,
    #[arg(long, default_value = "")]
    subdomain: String,
    #[arg(long, default_value = "cluster.local")]
    cluster_domain: String,
    #[arg(long)]
    pod_name: Option<String>,
    #[arg(long)]
    pod_ip: Option<String>,
    #[arg(long, default_value = "")]
    additional_dns_names: String,
    #[arg(long, default_value = "")]
    service_names: String,
    #[arg(long, default_value = "")]
    service_ips: String,
    #[arg(long, default_value_t = true)]
    wrap: bool,
    #[arg(long, default_value_t = true)]
    unwrap: bool,
}

#[derive(Parser)]
struct MaintainArgs {
    #[arg(long, default_value = "https://vault.cabotage.svc.cluster.local")]
    vault_addr: String,
    #[arg(long, default_value = "/var/run/secrets/cabotage.io/ca.crt")]
    vault_ca_file: String,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    vault_secrets_path: String,
    #[arg(long, default_value = "/var/run/secrets/vault/vault-token")]
    vault_token_file: String,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    consul_secrets_path: String,
    #[arg(long, default_value = "/var/run/secrets/vault")]
    cert_dir: String,
    #[arg(long, default_value = "cabotage-ca")]
    vault_pki_backend: String,
    #[arg(long)]
    vault_pki_role: Option<String>,
    #[arg(long, default_value_t = false)]
    unwrap: bool,
    #[arg(long, default_value = "/var/run/secrets/vault/vault-token")]
    write_vault_token_file: String,
}

#[derive(Parser)]
struct KubeLoginAndMaintainArgs {
    #[arg(long, default_value = "default")]
    namespace: String,
    #[arg(long, default_value = "https://vault.cabotage.svc.cluster.local")]
    vault_addr: String,
    #[arg(long, default_value = "/var/run/secrets/cabotage.io/ca.crt")]
    vault_ca_file: String,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    vault_secrets_path: String,
    #[arg(long)]
    vault_auth_kubernetes_role: Option<String>,
    #[arg(long, default_value = "auth/kubernetes/login")]
    vault_auth_kubernetes_backend: String,
    #[arg(long, default_value_t = false)]
    fetch_consul_token: bool,
    #[arg(long, default_value = "/var/run/secrets/vault/")]
    consul_secrets_path: String,
    #[arg(long)]
    vault_consul_role: Option<String>,
    #[arg(long, default_value = "cabotage-consul")]
    vault_consul_backend: String,
    #[arg(long, default_value_t = false)]
    fetch_cert: bool,
    #[arg(long, default_value = "/var/run/secrets/vault")]
    cert_dir: String,
    #[arg(long, default_value = "cabotage-ca")]
    vault_pki_backend: String,
    #[arg(long)]
    vault_pki_role: Option<String>,
    #[arg(long, default_value = "")]
    hostname: String,
    #[arg(long, default_value = "")]
    subdomain: String,
    #[arg(long, default_value = "cluster.local")]
    cluster_domain: String,
    #[arg(long)]
    pod_name: Option<String>,
    #[arg(long)]
    pod_ip: Option<String>,
    #[arg(long, default_value = "")]
    additional_dns_names: String,
    #[arg(long, default_value = "")]
    service_names: String,
    #[arg(long, default_value = "")]
    service_ips: String,
    #[arg(long, default_value_t = true)]
    wrap: bool,
    #[arg(long, default_value_t = true)]
    unwrap: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KubeLogin(args) => {
            let client = vault_client(&args.vault_ca_file)?;
            do_kube_login(
                &client,
                &args.vault_addr,
                &args.vault_ca_file,
                &args.vault_secrets_path,
                args.vault_auth_kubernetes_role.as_deref(),
                &args.vault_auth_kubernetes_backend,
                args.fetch_consul_token,
                &args.consul_secrets_path,
                args.vault_consul_role.as_deref(),
                &args.vault_consul_backend,
                args.fetch_cert,
                &args.cert_dir,
                &args.vault_pki_backend,
                args.vault_pki_role.as_deref(),
                &args.hostname,
                &args.subdomain,
                &args.cluster_domain,
                &args.namespace,
                args.pod_name.as_deref(),
                args.pod_ip.as_deref(),
                &args.additional_dns_names,
                &args.service_names,
                &args.service_ips,
                args.wrap,
                args.unwrap,
            )?;
        }
        Commands::Maintain(args) => {
            let client = vault_client(&args.vault_ca_file)?;
            let mut vault_token = fs::read_to_string(&args.vault_token_file)
                .with_context(|| format!("reading vault token from {}", args.vault_token_file))?;
            if args.unwrap {
                eprintln!("Unwrapping from stored wrapped token");
                match wrapping_token_lookup(&client, &args.vault_addr, &vault_token) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Issue looking up wrapping token ID!: {e}");
                        eprintln!("Something may be amiss!");
                    }
                }
                let unwrapped = unwrap_vault_response(&client, &args.vault_addr, &vault_token)?;
                vault_token = unwrapped["auth"]["client_token"]
                    .as_str()
                    .context("missing auth.client_token in unwrap response")?
                    .to_string();
                fs::write(&args.write_vault_token_file, &vault_token)?;
                if args.vault_token_file != args.write_vault_token_file {
                    fs::remove_file(&args.vault_token_file)?;
                }
            }
            do_maintain_loop(
                &client,
                &vault_token,
                &args.vault_addr,
                &args.vault_ca_file,
                &args.vault_secrets_path,
                &args.consul_secrets_path,
                &args.cert_dir,
                &args.vault_pki_backend,
                args.vault_pki_role.as_deref(),
            )?;
        }
        Commands::KubeLoginAndMaintain(args) => {
            let client = vault_client(&args.vault_ca_file)?;
            let token_contents = do_kube_login(
                &client,
                &args.vault_addr,
                &args.vault_ca_file,
                &args.vault_secrets_path,
                args.vault_auth_kubernetes_role.as_deref(),
                &args.vault_auth_kubernetes_backend,
                args.fetch_consul_token,
                &args.consul_secrets_path,
                args.vault_consul_role.as_deref(),
                &args.vault_consul_backend,
                args.fetch_cert,
                &args.cert_dir,
                &args.vault_pki_backend,
                args.vault_pki_role.as_deref(),
                &args.hostname,
                &args.subdomain,
                &args.cluster_domain,
                &args.namespace,
                args.pod_name.as_deref(),
                args.pod_ip.as_deref(),
                &args.additional_dns_names,
                &args.service_names,
                &args.service_ips,
                args.wrap,
                args.unwrap,
            )?;
            let vault_token = token_contents.context("no vault token from kube-login")?;
            do_maintain_loop(
                &client,
                &vault_token,
                &args.vault_addr,
                &args.vault_ca_file,
                &args.vault_secrets_path,
                &args.consul_secrets_path,
                &args.cert_dir,
                &args.vault_pki_backend,
                args.vault_pki_role.as_deref(),
            )?;
        }
    }

    Ok(())
}
