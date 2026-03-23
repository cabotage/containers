import random

import kopf
import kubernetes
from kubernetes.client.rest import ApiException


LABEL_KEY = "cabotage.io/tailscale-operator"
LABEL_VALUE = "true"



def _proxy_group_name(crd_name):
    return f"ingress-{crd_name}"


PROXY_GROUP_API = {
    "group": "tailscale.com",
    "version": "v1alpha1",
    "plural": "proxygroups",
}


def _labels(org_slug):
    return {
        LABEL_KEY: LABEL_VALUE,
        "organization": org_slug,
    }


# ---------------------------------------------------------------------------
# Kopf lifecycle
# ---------------------------------------------------------------------------


@kopf.on.startup()
def startup_fn(logger, memo, settings, **kwargs):
    settings.peering.priority = random.randint(0, 32767)
    settings.peering.name = "tailscale-operator-manager"
    settings.peering.clusterwide = True


# ---------------------------------------------------------------------------
# K8s helpers
# ---------------------------------------------------------------------------


def _ensure_resource(read_fn, create_fn, replace_fn, *args, **kwargs):
    """Generic create-or-update pattern."""
    resource = kwargs.pop("resource")
    try:
        read_fn(*args)
        replace_fn(*args, resource)
    except ApiException as exc:
        if exc.status == 404:
            # For create, the name is part of the resource body, not a positional arg
            # create_fn signature varies: (namespace, body) or just (body)
            create_fn(resource)
        else:
            raise


def _ensure_secret(core_api, namespace, name, string_data, labels):
    secret = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
        ),
        string_data=string_data,
    )
    try:
        core_api.read_namespaced_secret(name, namespace)
        core_api.replace_namespaced_secret(name, namespace, secret)
    except ApiException as exc:
        if exc.status == 404:
            core_api.create_namespaced_secret(namespace, secret)
        else:
            raise


def _ensure_service_account(core_api, namespace, name, labels):
    sa = kubernetes.client.V1ServiceAccount(
        metadata=kubernetes.client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
        ),
    )
    try:
        core_api.read_namespaced_service_account(name, namespace)
    except ApiException as exc:
        if exc.status == 404:
            core_api.create_namespaced_service_account(namespace, sa)
        else:
            raise


def _ensure_role(rbac_api, namespace, name, rules, labels):
    role = kubernetes.client.V1Role(
        metadata=kubernetes.client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
        ),
        rules=rules,
    )
    try:
        rbac_api.read_namespaced_role(name, namespace)
        rbac_api.replace_namespaced_role(name, namespace, role)
    except ApiException as exc:
        if exc.status == 404:
            rbac_api.create_namespaced_role(namespace, role)
        else:
            raise


def _ensure_role_binding(rbac_api, namespace, name, role_name, sa_name, labels):
    binding = kubernetes.client.V1RoleBinding(
        metadata=kubernetes.client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
        ),
        role_ref=kubernetes.client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="Role",
            name=role_name,
        ),
        subjects=[
            kubernetes.client.RbacV1Subject(
                kind="ServiceAccount",
                name=sa_name,
                namespace=namespace,
            ),
        ],
    )
    try:
        rbac_api.read_namespaced_role_binding(name, namespace)
        rbac_api.replace_namespaced_role_binding(name, namespace, binding)
    except ApiException as exc:
        if exc.status == 404:
            rbac_api.create_namespaced_role_binding(namespace, binding)
        else:
            raise


def _delete_if_exists(fn, *args, logger=None):
    try:
        fn(*args)
    except ApiException as exc:
        if exc.status != 404:
            if logger:
                logger.warning(f"Failed to delete {args}: {exc}")


TAILNET_API = {
    "group": "tailscale.com",
    "version": "v1alpha1",
    "plural": "tailnets",
}


def _ensure_tailnet(custom_api, crd_name, secret_name, labels, logger):
    """Create the Tailnet CRD so the operator authenticates to the org's tailnet."""
    body = {
        "apiVersion": f"{TAILNET_API['group']}/{TAILNET_API['version']}",
        "kind": "Tailnet",
        "metadata": {
            "name": crd_name,
            "labels": labels,
        },
        "spec": {
            "credentials": {
                "secretName": secret_name,
            },
        },
    }
    try:
        custom_api.get_cluster_custom_object(
            TAILNET_API["group"], TAILNET_API["version"],
            TAILNET_API["plural"], crd_name,
        )
        logger.info(f"Tailnet {crd_name} already exists")
    except ApiException as exc:
        if exc.status == 404:
            custom_api.create_cluster_custom_object(
                TAILNET_API["group"], TAILNET_API["version"],
                TAILNET_API["plural"], body,
            )
            logger.info(f"Created Tailnet {crd_name}")
        else:
            raise


def _delete_tailnet(custom_api, crd_name, logger):
    """Delete the Tailnet CRD."""
    try:
        custom_api.delete_cluster_custom_object(
            TAILNET_API["group"], TAILNET_API["version"],
            TAILNET_API["plural"], crd_name,
        )
        logger.info(f"Deleted Tailnet {crd_name}")
    except ApiException as exc:
        if exc.status != 404:
            logger.warning(f"Failed to delete Tailnet {crd_name}: {exc}")


def _ensure_proxy_group(custom_api, crd_name, labels, default_tags, logger):
    """Create the ProxyGroup so ingresses appear as Tailscale Services."""
    pg_name = _proxy_group_name(crd_name)
    spec = {
        "type": "ingress",
        "tailnet": crd_name,  # References the Tailnet CRD for this org
    }
    if default_tags:
        spec["tags"] = [t.strip() for t in default_tags.split(",") if t.strip()]
    body = {
        "apiVersion": f"{PROXY_GROUP_API['group']}/{PROXY_GROUP_API['version']}",
        "kind": "ProxyGroup",
        "metadata": {
            "name": pg_name,
            "labels": labels,
        },
        "spec": spec,
    }
    try:
        custom_api.get_cluster_custom_object(
            PROXY_GROUP_API["group"],
            PROXY_GROUP_API["version"],
            PROXY_GROUP_API["plural"],
            pg_name,
        )
        logger.info(f"ProxyGroup {pg_name} already exists")
    except ApiException as exc:
        if exc.status == 404:
            custom_api.create_cluster_custom_object(
                PROXY_GROUP_API["group"],
                PROXY_GROUP_API["version"],
                PROXY_GROUP_API["plural"],
                body,
            )
            logger.info(f"Created ProxyGroup {pg_name}")
        else:
            raise


def _delete_proxy_group(custom_api, crd_name, logger):
    """Delete the ProxyGroup."""
    pg_name = _proxy_group_name(crd_name)
    try:
        custom_api.delete_cluster_custom_object(
            PROXY_GROUP_API["group"],
            PROXY_GROUP_API["version"],
            PROXY_GROUP_API["plural"],
            pg_name,
        )
        logger.info(f"Deleted ProxyGroup {pg_name}")
    except ApiException as exc:
        if exc.status != 404:
            logger.warning(f"Failed to delete ProxyGroup {pg_name}: {exc}")


# ---------------------------------------------------------------------------
# RBAC rules for proxy pods (namespace-scoped)
# ---------------------------------------------------------------------------


def _proxies_role_rules():
    return [
        kubernetes.client.V1PolicyRule(
            api_groups=[""],
            resources=["secrets"],
            verbs=["get", "update", "patch", "create"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=[""],
            resources=["events"],
            verbs=["get", "create", "patch"],
        ),
    ]


# ---------------------------------------------------------------------------
# Reconciliation handlers
# ---------------------------------------------------------------------------


@kopf.on.create("cabotagetailscaleoperatorconfigs")
@kopf.on.update("cabotagetailscaleoperatorconfigs")
def reconcile_operator(spec, name, namespace, memo, logger, retry, **kwargs):
    if not spec and retry < 5:
        raise kopf.TemporaryError("spec is not yet populated", delay=1)

    client_id = spec["clientId"]
    operator_image = spec["operatorImage"]
    default_tags = spec.get("defaultTags", "")
    org_slug = spec["organizationSlug"]

    labels = _labels(org_slug)
    tailnet_secret_name = f"tailscale-tailnet-{name}"
    # The single operator runs in the cabotage namespace
    operator_namespace = "tailscale"

    core_api = kubernetes.client.CoreV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()

    # 1. Ensure Tailnet credential Secret exists in operator namespace
    #    (cabotage's refresh task writes client_id + jwt)
    try:
        core_api.read_namespaced_secret(tailnet_secret_name, operator_namespace)
        logger.info(f"Tailnet Secret {tailnet_secret_name} exists")
    except ApiException as exc:
        if exc.status == 404:
            _ensure_secret(
                core_api, operator_namespace, tailnet_secret_name,
                {"client_id": client_id, "jwt": ""},
                labels,
            )
            logger.info(f"Created placeholder Tailnet Secret {tailnet_secret_name}")
        else:
            raise

    # 2. Tailnet CRD (cluster-scoped) — references the credential Secret
    _ensure_tailnet(custom_api, name, tailnet_secret_name, labels, logger)

    # 3. ProxyGroup (cluster-scoped) — references the Tailnet
    _ensure_proxy_group(custom_api, name, labels, default_tags, logger)

    # 4. Proxies SA + RBAC in org namespace (for proxy pods)
    _ensure_service_account(core_api, namespace, "proxies", labels)
    _ensure_role(rbac_api, namespace, "proxies", _proxies_role_rules(), labels)
    _ensure_role_binding(rbac_api, namespace, "proxies", "proxies", "proxies", labels)
    logger.info("Ensured proxies RBAC")

    # Extract version from operator image tag
    version = operator_image.rsplit(":", 1)[-1] if ":" in operator_image else "unknown"

    return {"state": "deployed", "operatorVersion": version}


@kopf.on.delete("cabotagetailscaleoperatorconfigs")
def delete_operator(spec, name, namespace, logger, **kwargs):
    tailnet_secret_name = f"tailscale-tailnet-{name}"
    operator_namespace = "tailscale"

    core_api = kubernetes.client.CoreV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()

    # Delete in reverse order
    _delete_if_exists(
        rbac_api.delete_namespaced_role_binding, "proxies", namespace, logger=logger
    )
    _delete_if_exists(
        rbac_api.delete_namespaced_role, "proxies", namespace, logger=logger
    )
    _delete_if_exists(
        core_api.delete_namespaced_service_account, "proxies", namespace, logger=logger
    )
    _delete_proxy_group(custom_api, name, logger)
    _delete_tailnet(custom_api, name, logger)
    _delete_if_exists(
        core_api.delete_namespaced_secret,
        tailnet_secret_name, operator_namespace, logger=logger,
    )

    logger.info(f"Cleaned up Tailscale resources for {name}")
