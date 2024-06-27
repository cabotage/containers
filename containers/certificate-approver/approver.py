import base64
import datetime
import signal
import sys

import click
import kubernetes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from kubernetes.client.rest import ApiException


def signal_handler(signal, frame):
    click.echo("Exiting!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


@click.command()
@click.option(
    "--ca-secret_namespace",
    default="cabotage",
    help="Namespace to read to read ca secret from",
)
@click.option(
    "--ca-secret", default="certificate-approver-ca", help="Secret to read ca from"
)
@click.option("--api-group", default="certificates.k8s.io", help="apiGroup to check")
@click.option(
    "--resource",
    default="certificatesigningrequests",
    help="Resource in apiGroup to check",
)
@click.option("--subresource", default="serverautoapprove", help="Subresource to check")
@click.option("--verb", default="create", help="Verb to check")
@click.option("--act-as-signer", is_flag=True, help="Act as signer, requires --ca-secret")
def main(ca_secret_namespace, ca_secret, api_group, resource, subresource, verb, act_as_signer):
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

    v1 = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient())
    certificates_api = kubernetes.client.CertificatesV1Api(
        kubernetes.client.ApiClient()
    )
    authorization_api = kubernetes.client.AuthorizationV1Api(
        kubernetes.client.ApiClient()
    )

    w = kubernetes.watch.Watch()
    latest_resource_version = 0

    while True:
        for event in w.stream(
            certificates_api.list_certificate_signing_request,
            resource_version=latest_resource_version,
            timeout_seconds=10,
        ):
            if event["type"] != "ADDED":
                continue
            item = event["object"]
            latest_resource_version = max(
                latest_resource_version, int(item.metadata.resource_version)
            )

            try:
                certificate = certificates_api.read_certificate_signing_request(
                    item.metadata.name
                )
            except ApiException as e:
                if e.status == 404:
                    continue
                click.echo(
                    "Encournterd exception fetching CertificateSigningRequest %s: %s %s"
                    % (item.metadata.name, e.status, e.reason)
                )

            conditions = item.status.conditions or []
            if conditions:
                click.echo(
                    f'skipping {item.metadata.name} with status {",".join([c.type for c in item.status.conditions])}'
                )
                continue

            resource_attributes = kubernetes.client.V1ResourceAttributes(
                group=api_group,
                resource=resource,
                subresource=subresource,
                verb=verb,
            )
            subject_access_review_spec = kubernetes.client.V1SubjectAccessReviewSpec(
                extra=item.spec.extra,
                groups=item.spec.groups,
                uid=item.spec.uid,
                user=item.spec.username,
                resource_attributes=resource_attributes,
            )
            subject_access_review = kubernetes.client.V1SubjectAccessReview(
                spec=subject_access_review_spec
            )

            try:
                subject_access_review_response = (
                    authorization_api.create_subject_access_review(
                        subject_access_review
                    )
                )
            except ApiException as e:
                click.echo(
                    "Encountered exception creating SubjectAccessReview for %s: %s"
                    % (item.spec.username, e)
                )

            if not subject_access_review_response.status.allowed:
                click.echo(f"skipping unauthorized {item.metadata.name}")
                continue

            condition = kubernetes.client.models.V1CertificateSigningRequestCondition(
                type="Approved",
                status="True",
                reason="Auto Approved",
                message="Auto Approved by certificate-approver",
            )

            if act_as_signer:
                # sign the certificate
                ca_data = v1.read_namespaced_secret(ca_secret, ca_secret_namespace).data

                csr = x509.load_pem_x509_csr(base64.b64decode(item.spec.request))

                ca = x509.load_pem_x509_certificate(base64.b64decode(ca_data["tls.crt"]))
                ca_key = serialization.load_pem_private_key(
                    base64.b64decode(ca_data["tls.key"]), None
                )

                cert = (
                    x509.CertificateBuilder()
                    .subject_name(csr.subject)
                    .issuer_name(ca.subject)
                    .public_key(csr.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(
                        datetime.datetime.utcnow() + datetime.timedelta(days=366)
                    )
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    )
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                        critical=False,
                    )
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),
                        critical=False,
                    )
                )
                for extension in csr.extensions:
                    if isinstance(extension.value, x509.SubjectAlternativeName):
                        cert = cert.add_extension(
                            extension.value, critical=extension.critical
                        )

                signed_cert = cert.sign(ca_key, hashes.SHA256())
                chained_cert = signed_cert.public_bytes(
                    serialization.Encoding.PEM
                ) + ca.public_bytes(serialization.Encoding.PEM)

                status = kubernetes.client.models.V1CertificateSigningRequestStatus(
                    certificate=base64.b64encode(chained_cert).decode(),
                    conditions=[condition],
                )

                item.status = status

            else:
                status = kubernetes.client.models.V1CertificateSigningRequestStatus(
                    conditions=[condition],
                )

                item.status = status

            click.echo(f"approving {item.metadata.name}")
            try:
                certificates_api.replace_certificate_signing_request_approval(
                    item.metadata.name, item
                )
                if act_as_signer:
                    item = certificates_api.read_certificate_signing_request(
                        item.metadata.name
                    )
                    item.status = status
                    certificates_api.replace_certificate_signing_request_status(
                        item.metadata.name, item
                    )
            except ApiException as e:
                click.echo(
                    "Encountered exception approving CertificateSigningRequest %s: %s %s"
                    % (item.metadata.name, e.status, e.reason)
                )
                raise


if __name__ == "__main__":
    main()
