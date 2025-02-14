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


def policy_exists(vault_api, namespace, name):
    try:
        vault_api.sys.read_policy(f"{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        return False
    return True


def create_policy(vault_api, namespace, name):
    policy = VAULT_POLICY_TEMPLATE.format(namespace=namespace, name=name)
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


def create_consul_policy(consul_api, namespace, name):
    policy = CONSUL_POLICY_TEMPLATE.format(namespace=namespace, name=name)
    consul_api.acl.policy.create(name=f"{namespace}-{name}", rules=json.loads(policy))


def delete_consul_policy(consul_api, namespace, name):
    policy = consul_api.acl.policy.read(f"name/{namespace}-{name}")
    headers = consul_api.acl.policy.agent.prepare_headers(None)
    consul_api.acl.policy.agent.http.delete(
        CB.json(), f"/v1/acl/policy/{policy['ID']}", headers=headers
    )


@kopf.on.startup()
def startup_fn(logger, memo, settings, **kwargs):
    settings.peering.priority = random.randint(0, 32767)
    settings.peering.name = "enrollment-controller-operator"
    settings.peering.clusterwide = True

    with open("/var/run/secrets/vault/vault-token", "r") as f:
        vault_token = f.read()

    memo.vault_api = hvac.Client(
        url="https://vault.cabotage.svc.cluster.local",
        verify="/var/run/secrets/cabotage.io/ca.crt",
        token=vault_token,
    )

    with open("/var/run/secrets/vault/consul-token", "r") as f:
        consul_token = f.read()

    consul_addr_parsed = urlparse("https://consul.cabotage.svc.cluster.local:8443")
    memo.consul_api = consul.Consul(
        host=consul_addr_parsed.hostname,
        port=consul_addr_parsed.port,
        scheme=consul_addr_parsed.scheme,
        verify="/var/run/secrets/cabotage.io/ca.crt",
        token=consul_token,
    )


@kopf.on.probe(id="consul")
def check_consul_access(memo, **kwargs):
    memo.consul_api.status.leader()
    return True


@kopf.on.probe(id="vault")
def check_vault_access(memo, **kwargs):
    memo.vault_api.sys.read_leader_status()
    return True


@kopf.on.create("cabotageenrollments")
@kopf.on.update("cabotageenrollments")
def resource_vault_policy(spec, name, namespace, memo, logger, **kwargs):
    if policy_exists(memo.vault_api, namespace, name):
        logger.info(f"Vault policy {namespace}-{name} exists")
        return True
    else:
        logger.info(f"Creating Vault policy {namespace}-{name}")
        create_policy(memo.vault_api, namespace, name)
        return True


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
def resource_consul_policy(spec, name, namespace, memo, logger, **kwargs):
    if consul_policy_exists(
        memo.consul_api,
        namespace,
        name,
    ):
        logger.info(f"Consul policy {namespace}-{name} exists")
        return True
    else:
        logger.info(f"Creating Consul policy {namespace}-{name}")
        create_consul_policy(
            memo.consul_api,
            namespace,
            name,
        )
        return True


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
            if value:
                ready += 1
    _ready = False
    if ready == total:
        _ready = True

    return {"ready": _ready, "resources": f"{ready}/{total}"}


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
