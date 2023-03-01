import base64
import signal
import sys
import json
from urllib.parse import urlparse

import kubernetes
from kubernetes.client.rest import ApiException

import click

import consul
import hvac

import requests


def signal_handler(signal, frame):
    click.echo("Exiting!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def log_event(verb, event):
    click.echo(
        f"{verb} Event: {event['type']} {event['object'].metadata.resource_version}: {event['object'].kind} {event['object'].metadata.namespace}/{event['object'].metadata.name}  ({event['object'].metadata.uid})"
    )


CONSUL_POLICY_TEMPLATE = """
key_prefix "cabotage/{namespace}/{name}/" {{
  policy = "list"
}}

key_prefix "cabotage/{namespace}/{name}/mutable" {{
  policy = "write"
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


def delete_policy(vault_api, namespace, name):
    try:
        policy = vault_api.sys.read_policy(name=f"{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        click.echo(f"Policy {namespace}-{name} does not exist!")
        return
    click.echo(f"Policy {namespace}-{name} before delete:")
    click.echo(policy)
    vault_api.sys.delete_policy(name=f"{namespace}-{name}")


def role_exists(vault_api, namespace, name):
    try:
        role = vault_api.read(f"auth/kubernetes/role/{namespace}-{name}")
        return role != None
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


def delete_role(vault_api, namespace, name):
    try:
        role = vault_api.read(f"auth/kubernetes/role/{namespace}-{name}")
    except hvac.exceptions.InvalidPath:
        click.echo(f"Role {namespace}-{name} does not exist!")
        return
    click.echo(f"Role {namespace}-{name} before delete:")
    click.echo(role)
    vault_api.delete(f"auth/kubernetes/role/{namespace}-{name}")


def pki_role_exists(vault_api, namespace, name):
    try:
        role = vault_api.read(f"cabotage-ca/roles/{namespace}-{name}")
        return role != None
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
        policy = consul_api.acl.policy.get(name=f"{namespace}-{name}")
    except consul.base.ACLPermissionDenied:
        return False
    return True


def create_consul_policy(consul_api, namespace, name):
    policy = CONSUL_POLICY_TEMPLATE.format(namespace=namespace, name=name)
    consul_api.acl.policy.create(f"{namespace}-{name}", rules=policy)


def delete_consul_policy(consul_api, namespace, name):
    policy = consul_api.acl.policy.get(name=f"{namespace}-{name}")
    consul_api.acl.policy.delete(policy["ID"])


@click.command()
@click.option(
    "--vault-token",
    envvar="VAULT_TOKEN",
    help="The Vault authentication token. If not specified, will attempt to login to v1/auth/kubernetes/login",
)
@click.option(
    "--vault-addr",
    envvar="VAULT_ADDR",
    default="http://127.0.0.1:8200",
    help="The address of the Vault server expressed as a URL and port, for example: http://127.0.0.1:8200",
)
@click.option(
    "--vault-cacert",
    envvar="VAULT_CACERT",
    default="/var/run/secrets/cabotage.io/ca.crt",
    help="Path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.",
)
@click.option(
    "--consul-token",
    envvar="CONSUL_TOKEN",
    help="The Consul authentication token. If not specified, will attempt to login to v1/auth/kubernetes/login",
)
@click.option(
    "--consul-addr",
    envvar="CONSUL_ADDR",
    default="http://127.0.0.1:8500",
    help="The address of the Consul server expressed as a URL and port, for example: http://127.0.0.1:8500",
)
@click.option(
    "--consul-cacert",
    envvar="CONSUL_CACERT",
    default=True,
    help="Path to a PEM-encoded CA cert file to use to verify the Consul server SSL certificate.",
)
@click.option(
    "--serviceaccount-label",
    default="org.pypi.infra.vault-access",
    help="Kubernetes Annotation on ServiceAccounts to enroll",
)
def main(
    vault_token,
    vault_addr,
    vault_cacert,
    consul_token,
    consul_addr,
    consul_cacert,
    serviceaccount_label,
):
    try:
        click.echo("Loading incluster configuration...")
        kubernetes.config.load_incluster_config()
    except Exception as e:
        click.echo("Exception loading incluster configuration: %s" % e)
        try:
            click.echo("Loading kubernetes configuration...")
            kubernetes.config.load_kube_config()
        except Exception as e:
            click.echo("Exception loading kubernetes configuration: %s" % e)
            raise click.Abort()

    core_api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient())
    authorization_api = kubernetes.client.AuthorizationV1Api(
        kubernetes.client.ApiClient()
    )

    if vault_token is None:
        with open("/var/run/secrets/cabotage.io/token", "r") as f:
            jwt = f.read()
        token = requests.post(
            f"{vault_addr}/v1/auth/kubernetes/login",
            data=json.dumps({"jwt": jwt, "role": "vault-vault-enrollment-controller"}),
            verify=vault_ca_cert,
        )
        vault_token = token.json()["auth"]["client_token"]

    if vault_token.startswith("@"):
        with open(vault_token.lstrip("@"), "r") as f:
            vault_token = f.read()

    if vault_token is None:
        click.echo("No Vault Token available")
        raise click.Abort()

    vault_api = hvac.Client(url=vault_addr, verify=vault_cacert, token=vault_token)

    if consul_token is None:
        try:
            response = vault_api.read(
                f"cabotage-consul/roles/cabotage-enrollment-controller"
            )
            consul_token = response["token"]
        except hvac.exceptions.InvalidPath:
            consul_token = None

    if consul_token.startswith("@"):
        with open(consul_token.lstrip("@"), "r") as f:
            consul_token = f.read()

    if consul_token is None:
        click.echo("No Consul Token available")
        raise click.Abort()

    consul_addr_parsed = urlparse(consul_addr)
    consul_api = consul.Consul(
        host=consul_addr_parsed.hostname,
        port=consul_addr_parsed.port,
        scheme=consul_addr_parsed.scheme,
        verify=consul_cacert,
        token=consul_token,
    )

    w = kubernetes.watch.Watch()
    latest_resource_version = 0
    deleted = set()

    while True:
        try:
            for event in w.stream(
                core_api.list_service_account_for_all_namespaces,
                label_selector=f"{serviceaccount_label}=true",
                resource_version=latest_resource_version,
                timeout_seconds=10,
            ):
                if event["type"] == "DELETED":
                    item = event["object"]
                    if event["object"].metadata.uid in deleted:
                        continue

                    log_event("Handling Delete", event)

                    if role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Deleting Vault Kubernetes auth role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        delete_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )
                    else:
                        click.echo(
                            f"Vault Kubernetes auth role {item.metadata.namespace}-{item.metadata.name} already deleted"
                        )

                    if policy_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Deleting Vault policy {item.metadata.namespace}-{item.metadata.name}"
                        )
                        delete_policy(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )
                    else:
                        click.echo(
                            f"Vault Policy {item.metadata.namespace}-{item.metadata.name} already deleted"
                        )

                    if consul_role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Deleting Vault Consul role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        delete_consul_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )
                    else:
                        click.echo(
                            f"Vault Consul role {item.metadata.namespace}-{item.metadata.name} already deleted"
                        )

                    if consul_policy_exists(
                        consul_api,
                        item.metadata.namespace,
                        item.metadata.name,
                    ):
                        click.echo(
                            f"Deleting policy {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                        delete_consul_policy(
                            consul_api,
                            item.metadata.namespace,
                            item.metadata.name,
                        )
                    else:
                        click.echo(
                            f"Consul policy {item.metadata.namespace}-{item.metadata.name} already deleted"
                        )

                    if pki_role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Deleting Vault PKI role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        delete_pki_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )
                    else:
                        click.echo(
                            f"Vault PKI Policy {item.metadata.namespace}-{item.metadata.name} already deleted"
                        )

                    deleted.add(event["object"].metadata.uid)

                if event["type"] == "ADDED":
                    item = event["object"]
                    if (
                        item.metadata.labels
                        and serviceaccount_label not in item.metadata.labels
                    ):
                        log_event("Skipping Create", event)
                        continue

                    log_event("Handling Create", event)

                    deleted.discard(item.metadata.uid)

                    if policy_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Vault policy {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                    else:
                        click.echo(
                            f"Creating Vault policy {item.metadata.namespace}-{item.metadata.name}"
                        )
                        create_policy(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )

                    if role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Vault Kubernetes auth role {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                    else:
                        click.echo(
                            f"Creating Vault Kubernetes auth role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        create_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )

                    if consul_policy_exists(
                        consul_api,
                        item.metadata.namespace,
                        item.metadata.name,
                    ):
                        click.echo(
                            f"Consul policy {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                    else:
                        click.echo(
                            f"Creating Consul policy {item.metadata.namespace}-{item.metadata.name}"
                        )
                        create_consul_policy(
                            consul_api,
                            item.metadata.namespace,
                            item.metadata.name,
                        )

                    if consul_role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Vault Consul role {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                    else:
                        click.echo(
                            f"Creating Vault Consul role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        create_consul_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )

                    if pki_role_exists(
                        vault_api, item.metadata.namespace, item.metadata.name
                    ):
                        click.echo(
                            f"Vault PKI role {item.metadata.namespace}-{item.metadata.name} exists"
                        )
                    else:
                        click.echo(
                            f"Creating Vault PKI role {item.metadata.namespace}-{item.metadata.name}"
                        )
                        create_pki_role(
                            vault_api, item.metadata.namespace, item.metadata.name
                        )

                latest_resource_version = max(
                    latest_resource_version, int(item.metadata.resource_version)
                )

        except kubernetes.client.exceptions.ApiException:
            w = kubernetes.watch.Watch()
            latest_resource_version = 0
        except Exception as e:
            click.echo("Exception encountered: %s\n" % e)
            raise e
            sys.exit(1)


if __name__ == "__main__":
    main()
