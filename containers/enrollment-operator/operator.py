import json
import random
from urllib.parse import urlparse

import consul
import hvac
import kopf
from consul.callback import CB

CONSUL_POLICY_TEMPLATE = """
{{
    "key_prefix": {{
        "cabotage/{namespace}/{name}/": {{
            "policy": "list"
        }},
        "cabotage/{namespace}/{name}/mutable": {{
            "policy": "write"
        }}
    }}
}}
"""

CONSUL_POLICY_INHERITED_TEMPLATE = """
        "cabotage/{namespace}/{name}/": {{
            "policy": "list"
        }}
"""


VAULT_POLICY_TEMPLATE = """
path "cabotage-secrets/automation/{namespace}/{name}/*" {{
  capabilities = ["read", "update", "list"]
}}

path "cabotage-consul/creds/{namespace}-{name}" {{
  capabilities = ["read"]
}}

path "cabotage-ca/issue/{namespace}-{name}" {{
  capabilities = ["create", "update"]
}}
"""

VAULT_POLICY_INHERITED_TEMPLATE = """
path "cabotage-secrets/automation/{namespace}/{name}/*" {{
  capabilities = ["read", "list"]
}}
"""


def policy_exists(vault_api, namespace, name):
    try:
        vault_api.sys.read_policy(f"{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        return False
    return True


def _normalize_read_keys(read_keys):
    """Normalize read_keys dict to lowercase keys for consistent lookups."""
    if not read_keys:
        return {}
    return {k.lower(): v for k, v in read_keys.items()}


def create_policy(vault_api, namespace, name, inherits_from=None, read_keys=None):
    policy = VAULT_POLICY_TEMPLATE.format(namespace=namespace, name=name)
    for source in inherits_from or []:
        policy += VAULT_POLICY_INHERITED_TEMPLATE.format(
            namespace=source["namespace"], name=source["name"]
        )
    normalized = _normalize_read_keys(read_keys)
    for path in normalized.get("vault", []):
        policy += f"""
path "{path}" {{
  capabilities = ["read", "list"]
}}
"""
    vault_api.sys.create_or_update_policy(name=f"{namespace}-{name}", policy=policy)


def delete_policy(vault_api, logger, namespace, name):
    try:
        policy = vault_api.sys.read_policy(name=f"{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        logger.info(f"Policy {namespace}-{name} does not exist!")
        return
    logger.info(f"Policy {namespace}-{name} before delete:")
    logger.info(policy)
    vault_api.sys.delete_policy(name=f"{namespace}-{name}")


def role_exists(vault_api, namespace, name):
    try:
        role = vault_api.read(f"auth/kubernetes/role/{namespace}-{name}")
        return role is not None
    except hvac.exceptions.InvalidPath:
        return False
    return True


def create_role(vault_api, namespace, name):
    vault_api.write(
        f"auth/kubernetes/role/{namespace}-{name}",
        bound_service_account_names=[name],
        bound_service_account_namespaces=[namespace],
        policies=[f"{namespace}-{name}"],
        period=21600,
        ttl=21600,
        max_ttl=21600,
    )


def delete_role(vault_api, logger, namespace, name):
    try:
        role = vault_api.read(f"auth/kubernetes/role/{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        logger.info(f"Role {namespace}-{name} does not exist!")
        return
    logger.info(f"Role {namespace}-{name} before delete:")
    logger.info(role)
    vault_api.delete(f"auth/kubernetes/role/{namespace}-{name}")


def pki_role_exists(vault_api, namespace, name):
    try:
        role = vault_api.read(f"cabotage-ca/roles/{namespace}-{name}")
        return role is not None
    except hvac.exceptions.InvalidPath:
        return False
    return True


def create_pki_role(vault_api, namespace, name):
    vault_api.write(
        f"cabotage-ca/roles/{namespace}-{name}",
        ttl="168h",
        max_ttl="168h",
        key_type="ec",
        key_bits=256,
        generate_lease=True,
        organization="Cabotage Automated CA",
        ou=f"{namespace}-{name}",
        allow_localhost=False,
        allow_ip_sans=True,
        enforce_hostnames=True,
        allow_any_name=True,
    )  # TODO: Tighten this up! Research below options!
    """
    allowed_domains (list: []) – https://www.vaultproject.io/api/secret/pki/index.html#allowed_domains
    allow_bare_domains (bool: false) – https://www.vaultproject.io/api/secret/pki/index.html#allow_bare_domains
    allow_subdomains (bool: false) – https://www.vaultproject.io/api/secret/pki/index.html#allow_subdomains
    allow_glob_domains (bool: false) - https://www.vaultproject.io/api/secret/pki/index.html#allow_glob_domains
    """


def delete_pki_role(vault_api, namespace, name):
    vault_api.delete(f"cabotage-ca/roles/{namespace}-{name}")


def consul_role_exists(vault_api, namespace, name):
    result = vault_api.read(f"cabotage-consul/roles/{namespace}-{name}")
    if result is None:
        return False
    return True


def create_consul_role(vault_api, namespace, name):
    vault_api.write(
        f"cabotage-consul/roles/{namespace}-{name}",
        lease="21600s",
        consul_policies=[f"{namespace}-{name}"],
        token_type="client",
    )


def delete_consul_role(vault_api, namespace, name):
    vault_api.delete(f"cabotage-consul/roles/{namespace}-{name}")


def consul_policy_exists(consul_api, namespace, name):
    try:
        policy = consul_api.acl.policy.read(f"name/{namespace}-{name}")
        if not isinstance(policy, dict):
            # Return type of consul api changed in 1.18 anything but a dict
            # is a "Not Found"
            return False
    except consul.exceptions.ACLPermissionDenied:
        return False
    return True


def _build_consul_rules(namespace, name, inherits_from=None, read_keys=None):
    rules = json.loads(CONSUL_POLICY_TEMPLATE.format(namespace=namespace, name=name))
    for source in inherits_from or []:
        inherited = json.loads(
            "{"
            + CONSUL_POLICY_INHERITED_TEMPLATE.format(
                namespace=source["namespace"], name=source["name"]
            )
            + "}"
        )
        rules["key_prefix"].update(inherited)
    normalized = _normalize_read_keys(read_keys)
    for key_prefix in normalized.get("consul", []):
        rules["key_prefix"][key_prefix] = {"policy": "list"}
    return rules


def create_consul_policy(
    consul_api, namespace, name, inherits_from=None, read_keys=None
):
    rules = _build_consul_rules(namespace, name, inherits_from, read_keys)
    consul_api.acl.policy.create(name=f"{namespace}-{name}", rules=rules)


def update_consul_policy(
    consul_api, namespace, name, inherits_from=None, read_keys=None
):
    policy = consul_api.acl.policy.read(f"name/{namespace}-{name}")
    rules = _build_consul_rules(namespace, name, inherits_from, read_keys)
    headers = consul_api.acl.policy.agent.prepare_headers(None)
    consul_api.acl.policy.agent.http.put(
        CB.json(),
        f"/v1/acl/policy/{policy['ID']}",
        headers=headers,
        data=json.dumps({"Name": f"{namespace}-{name}", "Rules": json.dumps(rules)}),
    )


def delete_consul_policy(consul_api, namespace, name):
    policy = consul_api.acl.policy.read(f"name/{namespace}-{name}")
    headers = consul_api.acl.policy.agent.prepare_headers(None)
    consul_api.acl.policy.agent.http.delete(
        CB.json(), f"/v1/acl/policy/{policy['ID']}", headers=headers
    )


VAULT_TOKEN_PATH = "/var/run/secrets/vault/vault-token"
CONSUL_TOKEN_PATH = "/var/run/secrets/vault/consul-token"


@kopf.on.startup()
def startup_fn(logger, memo, settings, **kwargs):
    settings.peering.priority = random.randint(0, 32767)
    settings.peering.name = "enrollment-controller-operator"
    settings.peering.clusterwide = True

    with open(VAULT_TOKEN_PATH, "r") as f:
        vault_token = f.read()

    memo.vault_api = hvac.Client(
        url="https://vault.cabotage.svc.cluster.local",
        verify="/var/run/secrets/cabotage.io/ca.crt",
        token=vault_token,
    )

    with open(CONSUL_TOKEN_PATH, "r") as f:
        consul_token = f.read()

    consul_addr_parsed = urlparse("https://consul.cabotage.svc.cluster.local:8443")
    memo.consul_api = consul.Consul(
        host=consul_addr_parsed.hostname,
        port=consul_addr_parsed.port,
        scheme=consul_addr_parsed.scheme,
        verify="/var/run/secrets/cabotage.io/ca.crt",
        token=consul_token,
    )


def _refresh_vault_token(memo, logger):
    with open(VAULT_TOKEN_PATH, "r") as f:
        vault_token = f.read()
    if memo.vault_api.token != vault_token:
        logger.info("Vault token changed on disk, updating client")
        memo.vault_api.token = vault_token


def _refresh_consul_token(memo, logger):
    with open(CONSUL_TOKEN_PATH, "r") as f:
        consul_token = f.read()
    if memo.consul_api.token != consul_token:
        logger.info("Consul token changed on disk, updating client")
        memo.consul_api.token = consul_token


@kopf.on.probe(id="consul")
def check_consul_access(memo, logger, **kwargs):
    _refresh_consul_token(memo, logger)
    memo.consul_api.status.leader()
    return True


@kopf.on.probe(id="vault")
def check_vault_access(memo, logger, **kwargs):
    _refresh_vault_token(memo, logger)
    memo.vault_api.sys.read_leader_status()
    return True


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_vault_policy(spec, name, namespace, memo, logger, status, retry, **kwargs):
    if not spec and retry < 5:
        raise kopf.TemporaryError("spec is not yet populated", delay=1)
    inherits_from = spec.get("inheritsFrom", [])
    read_keys = spec.get("readKeys", {})
    last = status.get("resource_vault_policy", {})
    if isinstance(last, dict):
        last_read_keys = last.get("read_keys")
        last_inherits_from = last.get("inherits_from")
    else:
        last_read_keys = None
        last_inherits_from = None
    policy_current = read_keys == (last_read_keys or {}) and inherits_from == (
        last_inherits_from or []
    )
    if policy_exists(memo.vault_api, namespace, name) and policy_current:
        logger.info(f"Vault policy {namespace}-{name} exists and is current")
    else:
        logger.info(f"Creating/updating Vault policy {namespace}-{name}")
        create_policy(
            memo.vault_api,
            namespace,
            name,
            inherits_from=inherits_from,
            read_keys=read_keys,
        )
    return {
        "ready": True,
        "read_keys": read_keys or None,
        "inherits_from": inherits_from or None,
    }


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_vault_kubernetes_auth_role(spec, name, namespace, memo, logger, **kwargs):
    if role_exists(memo.vault_api, namespace, name):
        logger.info(f"Vault Kubernetes auth role {namespace}-{name} exists")
        return True
    else:
        logger.info(f"Creating Vault Kubernetes auth role {namespace}-{name}")
        create_role(memo.vault_api, namespace, name)
        return True


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_consul_policy(spec, name, namespace, memo, logger, status, retry, **kwargs):
    if not spec and retry < 5:
        raise kopf.TemporaryError("spec is not yet populated", delay=1)
    inherits_from = spec.get("inheritsFrom", [])
    read_keys = spec.get("readKeys", {})
    last = status.get("resource_consul_policy", {})
    if isinstance(last, dict):
        last_read_keys = last.get("read_keys")
        last_inherits_from = last.get("inherits_from")
    else:
        last_read_keys = None
        last_inherits_from = None
    policy_current = read_keys == (last_read_keys or {}) and inherits_from == (
        last_inherits_from or []
    )
    exists = consul_policy_exists(memo.consul_api, namespace, name)
    if exists and policy_current:
        logger.info(f"Consul policy {namespace}-{name} exists and is current")
    elif exists:
        logger.info(f"Updating Consul policy {namespace}-{name}")
        update_consul_policy(
            memo.consul_api,
            namespace,
            name,
            inherits_from=inherits_from,
            read_keys=read_keys,
        )
    else:
        logger.info(f"Creating Consul policy {namespace}-{name}")
        create_consul_policy(
            memo.consul_api,
            namespace,
            name,
            inherits_from=inherits_from,
            read_keys=read_keys,
        )
    return {
        "ready": True,
        "read_keys": read_keys or None,
        "inherits_from": inherits_from or None,
    }


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_vault_consul_role(spec, name, namespace, memo, logger, **kwargs):
    if consul_role_exists(memo.vault_api, namespace, name):
        logger.info(f"Vault Consul role {namespace}-{name} exists")
        return True
    else:
        logger.info(f"Creating Vault Consul role {namespace}-{name}")
        create_consul_role(memo.vault_api, namespace, name)
        return True


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_vault_pki_role(spec, name, namespace, memo, logger, **kwargs):
    if pki_role_exists(memo.vault_api, namespace, name):
        logger.info(f"Vault PKI role {namespace}-{name} exists")
        return True
    else:
        logger.info(f"Creating Vault PKI role {namespace}-{name}")
        create_pki_role(memo.vault_api, namespace, name)
        return True


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def summary(status, **kwargs):
    total = 0
    ready = 0
    for key, value in status.items():
        if key.startswith("resource_"):
            total += 1
            if value is True or (isinstance(value, dict) and value.get("ready")):
                ready += 1

    return {"ready": ready == total, "resources": f"{ready}/{total}"}


@kopf.on.delete("cabotageenrollments")
def delete_fn(spec, name, namespace, memo, logger, **kwargs):
    if role_exists(memo.vault_api, namespace, name):
        logger.info(f"Deleting Vault Kubernetes auth role {namespace}-{name}")
        delete_role(memo.vault_api, logger, namespace, name)
    else:
        logger.info(f"Vault Kubernetes auth role {namespace}-{name} already deleted")

    if policy_exists(memo.vault_api, namespace, name):
        logger.info(f"Deleting Vault policy {namespace}-{name}")
        delete_policy(memo.vault_api, logger, namespace, name)
    else:
        logger.info(f"Vault Policy {namespace}-{name} already deleted")

    if consul_role_exists(memo.vault_api, namespace, name):
        logger.info(f"Deleting Vault Consul role {namespace}-{name}")
        delete_consul_role(memo.vault_api, namespace, name)
    else:
        logger.info(f"Vault Consul role {namespace}-{name} already deleted")

    if consul_policy_exists(
        memo.consul_api,
        namespace,
        name,
    ):
        logger.info(f"Deleting policy {namespace}-{name} exists")
        delete_consul_policy(
            memo.consul_api,
            namespace,
            name,
        )
    else:
        logger.info(f"Consul policy {namespace}-{name} already deleted")

    if pki_role_exists(memo.vault_api, namespace, name):
        logger.info(f"Deleting Vault PKI role {namespace}-{name}")
        delete_pki_role(memo.vault_api, namespace, name)
    else:
        logger.info(f"Vault PKI Policy {namespace}-{name} already deleted")
