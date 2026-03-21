import random

import hvac
import kopf
import kubernetes
from kubernetes.client.rest import ApiException


VAULT_TOKEN_PATH = "/var/run/secrets/vault/vault-token"

LABEL_KEY = "cabotage.io/tailscale-operator"
LABEL_VALUE = "true"

# ClusterRoleBinding that all per-namespace operator SAs get added to
CLUSTER_ROLE_BINDING_NAME = "tailscale-operator"


def _operator_name(crd_name):
    return f"tailscale-operator-{crd_name}"


def _oauth_secret_name(crd_name):
    return f"tailscale-oauth-{crd_name}"


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

    with open(VAULT_TOKEN_PATH, "r") as f:
        vault_token = f.read()

    memo.vault_api = hvac.Client(
        url="https://vault.cabotage.svc.cluster.local",
        verify="/var/run/secrets/cabotage.io/ca.crt",
        token=vault_token,
    )


def _refresh_vault_token(memo, logger):
    with open(VAULT_TOKEN_PATH, "r") as f:
        vault_token = f.read()
    if memo.vault_api.token != vault_token:
        logger.info("Vault token changed on disk, updating client")
        memo.vault_api.token = vault_token


@kopf.on.probe(id="vault")
def check_vault_access(memo, logger, **kwargs):
    _refresh_vault_token(memo, logger)
    memo.vault_api.sys.read_leader_status()
    return True


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
            name=name, namespace=namespace, labels=labels,
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
            name=name, namespace=namespace, labels=labels,
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
            name=name, namespace=namespace, labels=labels,
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
            name=name, namespace=namespace, labels=labels,
        ),
        role_ref=kubernetes.client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="Role",
            name=role_name,
        ),
        subjects=[
            kubernetes.client.RbacV1Subject(
                kind="ServiceAccount", name=sa_name, namespace=namespace,
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
            logger.warning(
                f"ClusterRoleBinding {CLUSTER_ROLE_BINDING_NAME} not found"
            )
            return
        raise

    subjects = crb.subjects or []
    if any(s.name == sa_name and s.namespace == namespace for s in subjects):
        return

    subjects.append(
        kubernetes.client.RbacV1Subject(
            kind="ServiceAccount", name=sa_name, namespace=namespace,
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
    filtered = [s for s in subjects if not (s.name == sa_name and s.namespace == namespace)]
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


# ---------------------------------------------------------------------------
# Operator role rules (what the Tailscale operator needs within its namespace)
# ---------------------------------------------------------------------------

def _operator_role_rules():
    return [
        kubernetes.client.V1PolicyRule(
            api_groups=[""],
            resources=["secrets", "serviceaccounts", "configmaps", "events"],
            verbs=["get", "list", "watch", "create", "update", "patch", "delete"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=[""],
            resources=["services", "services/status"],
            verbs=["get", "list", "watch", "update", "patch"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=[""],
            resources=["pods"],
            verbs=["get", "list", "watch"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=["apps"],
            resources=["statefulsets", "deployments"],
            verbs=["get", "list", "watch", "create", "update", "patch", "delete"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=["networking.k8s.io"],
            resources=["ingresses", "ingresses/status"],
            verbs=["get", "list", "watch", "update", "patch"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=["tailscale.com"],
            resources=["*"],
            verbs=["get", "list", "watch", "create", "update", "patch", "delete"],
        ),
        kubernetes.client.V1PolicyRule(
            api_groups=["coordination.k8s.io"],
            resources=["leases"],
            verbs=["get", "list", "watch", "create", "update", "patch"],
        ),
    ]


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

    _refresh_vault_token(memo, logger)

    vault_path = spec["vaultPath"]
    operator_image = spec["operatorImage"]
    default_tags = spec.get("defaultTags", "")
    org_slug = spec["organizationSlug"]

    # Read credentials from Vault
    creds = memo.vault_api.read(vault_path)
    if creds is None or "data" not in creds:
        raise kopf.TemporaryError(
            f"No credentials found at Vault path {vault_path}", delay=30,
        )
    client_id = creds["data"]["client_id"]
    client_secret = creds["data"]["client_secret"]

    labels = _labels(org_slug)
    operator_sa = _operator_name(name)
    secret_name = _oauth_secret_name(name)

    core_api = kubernetes.client.CoreV1Api()
    apps_api = kubernetes.client.AppsV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()

    # 1. OAuth Secret
    _ensure_secret(core_api, namespace, secret_name, {
        "client_id": client_id,
        "client_secret": client_secret,
    }, labels)
    logger.info(f"Ensured OAuth Secret {secret_name}")

    # 2. ServiceAccounts
    _ensure_service_account(core_api, namespace, operator_sa, labels)
    _ensure_service_account(core_api, namespace, "proxies", labels)
    logger.info("Ensured ServiceAccounts")

    # 3. Operator Role + RoleBinding
    _ensure_role(rbac_api, namespace, operator_sa, _operator_role_rules(), labels)
    _ensure_role_binding(rbac_api, namespace, operator_sa, operator_sa, operator_sa, labels)
    logger.info("Ensured operator RBAC")

    # 4. Proxies Role + RoleBinding
    _ensure_role(rbac_api, namespace, "proxies", _proxies_role_rules(), labels)
    _ensure_role_binding(rbac_api, namespace, "proxies", "proxies", "proxies", labels)
    logger.info("Ensured proxies RBAC")

    # 5. ClusterRoleBinding subject
    _ensure_cluster_role_binding_subject(rbac_api, namespace, operator_sa, logger)

    # 6. Operator Deployment
    deploy_name = operator_sa
    env_vars = [
        kubernetes.client.V1EnvVar(name="OPERATOR_HOSTNAME", value=f"ts-operator-{namespace}"),
        kubernetes.client.V1EnvVar(name="OPERATOR_NAMESPACE", value=namespace),
        kubernetes.client.V1EnvVar(name="OPERATOR_SECRET", value=f"{deploy_name}-state"),
        kubernetes.client.V1EnvVar(name="CLIENT_ID_FILE", value="/oauth/client_id"),
        kubernetes.client.V1EnvVar(name="CLIENT_SECRET_FILE", value="/oauth/client_secret"),
    ]
    if default_tags:
        env_vars.append(
            kubernetes.client.V1EnvVar(name="OPERATOR_INITIAL_TAGS", value=default_tags)
        )

    deploy_labels = {**labels, "app": deploy_name}
    deployment = kubernetes.client.V1Deployment(
        metadata=kubernetes.client.V1ObjectMeta(
            name=deploy_name, namespace=namespace, labels=deploy_labels,
        ),
        spec=kubernetes.client.V1DeploymentSpec(
            replicas=1,
            selector=kubernetes.client.V1LabelSelector(match_labels={"app": deploy_name}),
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
                                    name="oauth", mount_path="/oauth", read_only=True,
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
                            name="oauth",
                            secret=kubernetes.client.V1SecretVolumeSource(
                                secret_name=secret_name,
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

    # Extract version from image tag
    version = operator_image.rsplit(":", 1)[-1] if ":" in operator_image else "unknown"

    return {"state": "deployed", "operatorVersion": version}


@kopf.on.delete("cabotagetailscaleoperatorconfigs")
def delete_operator(spec, name, namespace, logger, **kwargs):
    org_slug = spec.get("organizationSlug", "")
    operator_sa = _operator_name(name)
    secret_name = _oauth_secret_name(name)

    core_api = kubernetes.client.CoreV1Api()
    apps_api = kubernetes.client.AppsV1Api()
    rbac_api = kubernetes.client.RbacAuthorizationV1Api()

    # Delete in reverse order
    _delete_if_exists(apps_api.delete_namespaced_deployment, operator_sa, namespace, logger=logger)
    _delete_if_exists(rbac_api.delete_namespaced_role_binding, operator_sa, namespace, logger=logger)
    _delete_if_exists(rbac_api.delete_namespaced_role, operator_sa, namespace, logger=logger)
    _delete_if_exists(rbac_api.delete_namespaced_role_binding, "proxies", namespace, logger=logger)
    _delete_if_exists(rbac_api.delete_namespaced_role, "proxies", namespace, logger=logger)
    _delete_if_exists(core_api.delete_namespaced_service_account, operator_sa, namespace, logger=logger)
    _delete_if_exists(core_api.delete_namespaced_service_account, "proxies", namespace, logger=logger)
    _delete_if_exists(core_api.delete_namespaced_secret, secret_name, namespace, logger=logger)
    _delete_if_exists(core_api.delete_namespaced_secret, f"{operator_sa}-state", namespace, logger=logger)

    _remove_cluster_role_binding_subject(rbac_api, namespace, operator_sa, logger)

    logger.info(f"Cleaned up all Tailscale operator resources in {namespace}")
