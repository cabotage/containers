import random

import kopf
import kubernetes
from kubernetes.client.rest import ApiException


LABEL_KEY = "cabotage.io/tailscale-operator"
LABEL_VALUE = "true"

# ClusterRoleBinding that all per-namespace operator SAs get added to
CLUSTER_ROLE_BINDING_NAME = "tailscale-operator"


def _operator_name(crd_name):
    return f"tailscale-operator-{crd_name}"


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


def _ensure_cluster_role_binding_subject(rbac_api, namespace, sa_name, logger):
    """Add a ServiceAccount to the pre-provisioned tailscale-operator ClusterRoleBinding."""
    try:
        crb = rbac_api.read_cluster_role_binding(CLUSTER_ROLE_BINDING_NAME)
    except ApiException as exc:
        if exc.status == 404:
            logger.warning(f"ClusterRoleBinding {CLUSTER_ROLE_BINDING_NAME} not found")
            return
        raise

    subjects = crb.subjects or []
    if any(s.name == sa_name and s.namespace == namespace for s in subjects):
        return

    subjects.append(
        kubernetes.client.RbacV1Subject(
            kind="ServiceAccount",
            name=sa_name,
            namespace=namespace,
        )
    )
    crb.subjects = subjects
    rbac_api.replace_cluster_role_binding(CLUSTER_ROLE_BINDING_NAME, crb)
    logger.info(f"Added {sa_name} in {namespace} to ClusterRoleBinding")


def _remove_cluster_role_binding_subject(rbac_api, namespace, sa_name, logger):
    """Remove a ServiceAccount from the ClusterRoleBinding."""
    try:
        crb = rbac_api.read_cluster_role_binding(CLUSTER_ROLE_BINDING_NAME)
    except ApiException as exc:
        if exc.status == 404:
            return
        raise

    subjects = crb.subjects or []
    filtered = [
        s for s in subjects if not (s.name == sa_name and s.namespace == namespace)
    ]
    if len(filtered) == len(subjects):
        return

    crb.subjects = filtered
    rbac_api.replace_cluster_role_binding(CLUSTER_ROLE_BINDING_NAME, crb)
    logger.info(f"Removed {sa_name} in {namespace} from ClusterRoleBinding")


def _delete_if_exists(fn, *args, logger=None):
    try:
        fn(*args)
    except ApiException as exc:
        if exc.status != 404:
            if logger:
                logger.warning(f"Failed to delete {args}: {exc}")


def _ingress_class_name(crd_name):
    return f"tailscale-{crd_name}"


def _ensure_ingress_class(networking_api, crd_name, labels, logger):
    """Create per-org IngressClass so the operator only watches its own ingresses."""
    ic_name = _ingress_class_name(crd_name)
    body = kubernetes.client.V1IngressClass(
        metadata=kubernetes.client.V1ObjectMeta(
            name=ic_name,
            labels=labels,
        ),
        spec=kubernetes.client.V1IngressClassSpec(
            controller="tailscale.com/ts-ingress",
        ),
    )
    try:
        networking_api.read_ingress_class(ic_name)
        logger.info(f"IngressClass {ic_name} already exists")
    except ApiException as exc:
        if exc.status == 404:
            networking_api.create_ingress_class(body)
            logger.info(f"Created IngressClass {ic_name}")
        else:
            raise


def _delete_ingress_class(networking_api, crd_name, logger):
    """Delete per-org IngressClass."""
    ic_name = _ingress_class_name(crd_name)
    try:
        networking_api.delete_ingress_class(ic_name)
        logger.info(f"Deleted IngressClass {ic_name}")
    except ApiException as exc:
        if exc.status != 404:
            logger.warning(f"Failed to delete IngressClass {ic_name}: {exc}")


def _ensure_proxy_group(custom_api, crd_name, labels, default_tags, logger):
    """Create the ProxyGroup so ingresses appear as Tailscale Services."""
    pg_name = _proxy_group_name(crd_name)
    spec = {"type": "ingress"}
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
    operator_sa = _operator_name(name)
    jwt_secret_name = f"tailscale-oidc-jwt-{name}"

    core_api = kubernetes.client.CoreV1Api()
    apps_api = kubernetes.client.AppsV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()

    # 1. Ensure JWT Secret exists (cabotage's refresh task writes the token)
    try:
        core_api.read_namespaced_secret(jwt_secret_name, namespace)
        logger.info(f"JWT Secret {jwt_secret_name} exists")
    except ApiException as exc:
        if exc.status == 404:
            # Create placeholder — cabotage's periodic task will populate it
            _ensure_secret(
                core_api, namespace, jwt_secret_name,
                {"token": ""},
                labels,
            )
            logger.info(f"Created placeholder JWT Secret {jwt_secret_name}")
        else:
            raise

    # 2. Per-org IngressClass
    networking_api = kubernetes.client.NetworkingV1Api()
    _ensure_ingress_class(networking_api, name, labels, logger)

    # 3. ServiceAccounts
    _ensure_service_account(core_api, namespace, operator_sa, labels)
    _ensure_service_account(core_api, namespace, "proxies", labels)
    logger.info("Ensured ServiceAccounts")

    # 3. ClusterRoleBinding subject (grants operator cluster-wide access
    #    via the pre-provisioned tailscale-operator ClusterRole — no
    #    redundant namespace Role needed)
    _ensure_cluster_role_binding_subject(rbac_api, namespace, operator_sa, logger)

    # 4. Proxies Role + RoleBinding (proxies don't have a ClusterRole,
    #    they only need namespace-scoped secret access for their state)
    _ensure_role(rbac_api, namespace, "proxies", _proxies_role_rules(), labels)
    _ensure_role_binding(rbac_api, namespace, "proxies", "proxies", "proxies", labels)
    logger.info("Ensured proxies RBAC")

    # 6. Operator Deployment (WIF mode — JWT from cabotage OIDC issuer)
    deploy_name = operator_sa
    env_vars = [
        kubernetes.client.V1EnvVar(
            name="OPERATOR_HOSTNAME", value=f"ts-operator-{namespace}"
        ),
        kubernetes.client.V1EnvVar(name="OPERATOR_NAMESPACE", value=namespace),
        kubernetes.client.V1EnvVar(
            name="OPERATOR_SECRET", value=f"{deploy_name}-state"
        ),
        # CLIENT_ID (not CLIENT_ID_FILE) triggers WIF mode in the operator
        kubernetes.client.V1EnvVar(name="CLIENT_ID", value=client_id),
        # Per-org IngressClass so this operator only watches its own ingresses
        kubernetes.client.V1EnvVar(
            name="OPERATOR_INGRESS_CLASS_NAME", value=_ingress_class_name(name)
        ),
    ]
    if default_tags:
        env_vars.append(
            kubernetes.client.V1EnvVar(name="OPERATOR_INITIAL_TAGS", value=default_tags)
        )

    deploy_labels = {**labels, "app": deploy_name}
    deployment = kubernetes.client.V1Deployment(
        metadata=kubernetes.client.V1ObjectMeta(
            name=deploy_name,
            namespace=namespace,
            labels=deploy_labels,
        ),
        spec=kubernetes.client.V1DeploymentSpec(
            replicas=1,
            selector=kubernetes.client.V1LabelSelector(
                match_labels={"app": deploy_name}
            ),
            template=kubernetes.client.V1PodTemplateSpec(
                metadata=kubernetes.client.V1ObjectMeta(labels=deploy_labels),
                spec=kubernetes.client.V1PodSpec(
                    service_account_name=deploy_name,
                    containers=[
                        kubernetes.client.V1Container(
                            name="operator",
                            image=operator_image,
                            env=env_vars,
                            volume_mounts=[
                                kubernetes.client.V1VolumeMount(
                                    name="oidc-jwt",
                                    mount_path="/var/run/secrets/tailscale/serviceaccount",
                                    read_only=True,
                                ),
                            ],
                            resources=kubernetes.client.V1ResourceRequirements(
                                requests={"cpu": "50m", "memory": "64Mi"},
                                limits={"cpu": "200m", "memory": "128Mi"},
                            ),
                        ),
                    ],
                    volumes=[
                        kubernetes.client.V1Volume(
                            name="oidc-jwt",
                            secret=kubernetes.client.V1SecretVolumeSource(
                                secret_name=jwt_secret_name,
                            ),
                        ),
                    ],
                ),
            ),
        ),
    )
    try:
        apps_api.read_namespaced_deployment(deploy_name, namespace)
        apps_api.replace_namespaced_deployment(deploy_name, namespace, deployment)
    except ApiException as exc:
        if exc.status == 404:
            apps_api.create_namespaced_deployment(namespace, deployment)
        else:
            raise
    logger.info(f"Ensured Deployment {deploy_name}")

    # 7. ProxyGroup for HA ingress (Tailscale Services instead of devices)
    _ensure_proxy_group(custom_api, name, labels, default_tags, logger)

    # Extract version from image tag
    version = operator_image.rsplit(":", 1)[-1] if ":" in operator_image else "unknown"

    return {"state": "deployed", "operatorVersion": version}


@kopf.on.delete("cabotagetailscaleoperatorconfigs")
def delete_operator(spec, name, namespace, logger, **kwargs):
    org_slug = spec.get("organizationSlug", "")
    operator_sa = _operator_name(name)
    jwt_secret_name = f"tailscale-oidc-jwt-{name}"

    core_api = kubernetes.client.CoreV1Api()
    apps_api = kubernetes.client.AppsV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()

    # Delete in reverse order
    networking_api = kubernetes.client.NetworkingV1Api()
    _delete_ingress_class(networking_api, name, logger)
    _delete_proxy_group(custom_api, name, logger)
    _delete_if_exists(
        apps_api.delete_namespaced_deployment, operator_sa, namespace, logger=logger
    )
    _delete_if_exists(
        rbac_api.delete_namespaced_role_binding, "proxies", namespace, logger=logger
    )
    _delete_if_exists(
        rbac_api.delete_namespaced_role, "proxies", namespace, logger=logger
    )
    _delete_if_exists(
        core_api.delete_namespaced_service_account,
        operator_sa,
        namespace,
        logger=logger,
    )
    _delete_if_exists(
        core_api.delete_namespaced_service_account, "proxies", namespace, logger=logger
    )
    _delete_if_exists(
        core_api.delete_namespaced_secret, jwt_secret_name, namespace, logger=logger
    )
    _delete_if_exists(
        core_api.delete_namespaced_secret,
        f"{operator_sa}-state",
        namespace,
        logger=logger,
    )

    _remove_cluster_role_binding_subject(rbac_api, namespace, operator_sa, logger)

    logger.info(f"Cleaned up all Tailscale operator resources in {namespace}")
