import base64
import json

from aiohttp import web


projected_volume = {
    "name": "cabotage-ca",
    "projected": {
        "defaultMode": 422,
        "sources": [
            {
                "configMap": {
                    "name": "cabotage-ca",
                }
            },
        ],
    },
}

projected_volume_mount = {
    "mountPath": "/var/run/secrets/cabotage.io",
    "name": "cabotage-ca",
}


async def mutate(request):
    admission_review = await request.json()
    uid = admission_review["request"]["uid"]

    ops = []
    if admission_review["request"]["object"]["spec"].get("volumes", None) is None:
        ops = [{"op": "add", "path": "/spec/volumes", "value": []}]
    ops.append({"op": "add", "path": "/spec/volumes/-", "value": projected_volume})

    for i, init_container in enumerate(
        admission_review["request"]["object"]["spec"].get("initContainers", [])
    ):
        if init_container.get("volumeMounts", None) is None:
            ops.append(
                {
                    "op": "add",
                    "path": f"/spec/initContainers/{i}/volumeMounts",
                    "value": [],
                }
            )
        ops.append(
            {
                "op": "add",
                "path": f"/spec/initContainers/{i}/volumeMounts/-",
                "value": projected_volume_mount,
            }
        )

    for i, container in enumerate(
        admission_review["request"]["object"]["spec"].get("containers", [])
    ):
        if container.get("volumeMounts", None) is None:
            ops.append(
                {
                    "op": "add",
                    "path": f"/spec/containers/{i}/volumeMounts",
                    "value": [],
                }
            )
        ops.append(
            {
                "op": "add",
                "path": f"/spec/containers/{i}/volumeMounts/-",
                "value": projected_volume_mount,
            }
        )

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
            "patchType": "JSONPatch",
            "patch": base64.b64encode(json.dumps(ops).encode()).decode(),
            "status": {"message": "Attaching cabotage-ca projected volume to pods..."},
        },
    }

    return web.json_response(response)


async def health(_):
    return web.json_response("OK")


async def app():
    _app = web.Application()
    _app.router.add_get("/_health", health)
    _app.router.add_post("/mutate", mutate)
    return _app
