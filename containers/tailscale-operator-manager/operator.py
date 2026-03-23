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
        existing = custom_api.get_cluster_custom_object(
            TAILNET_API["group"], TAILNET_API["version"],
            TAILNET_API["plural"], crd_name,
        )
        existing_secret = existing.get("spec", {}).get("credentials", {}).get("secretName", "")
        if existing_secret != secret_name:
            logger.info(
                f"Tailnet {crd_name} has secretName={existing_secret!r}, "
                f"expected {secret_name!r} — recreating"
            )
            custom_api.delete_cluster_custom_object(
                TAILNET_API["group"], TAILNET_API["version"],
                TAILNET_API["plural"], crd_name,
            )
            custom_api.create_cluster_custom_object(
                TAILNET_API["group"], TAILNET_API["version"],
                TAILNET_API["plural"], body,
            )
            logger.info(f"Recreated Tailnet {crd_name}")
        else:
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
            raise


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
        existing = custom_api.get_cluster_custom_object(
            PROXY_GROUP_API["group"],
            PROXY_GROUP_API["version"],
            PROXY_GROUP_API["plural"],
            pg_name,
        )
        # spec.tailnet is immutable and tags require new auth keys —
        # if either differs, delete and recreate
        existing_spec = existing.get("spec", {})
        existing_tailnet = existing_spec.get("tailnet", "")
        existing_tags = existing_spec.get("tags", [])
        expected_tags = spec.get("tags", [])
        needs_recreate = (existing_tailnet != crd_name) or (existing_tags != expected_tags)
        if needs_recreate:
            logger.info(
                f"ProxyGroup {pg_name} has tailnet={existing_tailnet!r} tags={existing_tags!r}, "
                f"expected tailnet={crd_name!r} tags={expected_tags!r} — recreating"
            )
            custom_api.delete_cluster_custom_object(
                PROXY_GROUP_API["group"],
                PROXY_GROUP_API["version"],
                PROXY_GROUP_API["plural"],
                pg_name,
            )
            custom_api.create_cluster_custom_object(
                PROXY_GROUP_API["group"],
                PROXY_GROUP_API["version"],
                PROXY_GROUP_API["plural"],
                body,
            )
            logger.info(f"Recreated ProxyGroup {pg_name} with tailnet={crd_name}")
        else:
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
            raise


# ---------------------------------------------------------------------------
# Reconciliation handlers
# ---------------------------------------------------------------------------


@kopf.on.create("cabotagetailscaleoperatorconfigs")
@kopf.on.update("cabotagetailscaleoperatorconfigs")
def reconcile_operator(spec, name, namespace, memo, logger, retry, **kwargs):
    if not spec and retry < 5:
        raise kopf.TemporaryError("spec is not yet populated", delay=1)
    if not spec:
        raise kopf.PermanentError("spec is empty after 5 retries, giving up")

    default_tags = spec.get("defaultTags", "")
    default_tags = spec.get("defaultTags", "")
    org_slug = spec["organizationSlug"]

    labels = _labels(org_slug)
    tailnet_secret_name = f"tailscale-tailnet-{name}"

    custom_api = kubernetes.client.CustomObjectsApi()

    # 1. Tailnet CRD (cluster-scoped) — references the credential Secret
    #    (cabotage-app creates the Secret before enqueuing the CRD)
    _ensure_tailnet(custom_api, name, tailnet_secret_name, labels, logger)

    # 2. ProxyGroup (cluster-scoped) — references the Tailnet
    _ensure_proxy_group(custom_api, name, labels, default_tags, logger)

    return {"state": "deployed"}


@kopf.on.delete("cabotagetailscaleoperatorconfigs")
def delete_operator(spec, name, namespace, logger, **kwargs):
    custom_api = kubernetes.client.CustomObjectsApi()

    # Delete in reverse order
    _delete_proxy_group(custom_api, name, logger)
    _delete_tailnet(custom_api, name, logger)

    logger.info(f"Cleaned up Tailscale resources for {name}")
