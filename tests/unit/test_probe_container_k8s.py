"""Smoke tests for container/K8s batch — most won't apply on the test host."""
import shutil

import pytest

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.container_image_sbom import ContainerImageSbom
from pqcscan.probes.container_runtime_detect import ContainerRuntimeDetect
from pqcscan.probes.k8s_helm_releases import K8sHelmReleases
from pqcscan.probes.k8s_ingress_tls import K8sIngressTls
from pqcscan.probes.k8s_mesh_mtls import K8sMeshMtls
from pqcscan.probes.k8s_secrets_types import K8sSecretsTypes


@pytest.mark.parametrize(
    "cls,probe_id,family",
    [
        (ContainerRuntimeDetect, "container.runtime.detect", ProbeFamily.CONTAINER),
        (ContainerImageSbom,     "container.image.sbom",     ProbeFamily.CONTAINER),
        (K8sIngressTls,          "k8s.ingress.tls",          ProbeFamily.CONTAINER),
        (K8sSecretsTypes,        "k8s.secrets.types",        ProbeFamily.CONTAINER),
        (K8sHelmReleases,        "k8s.helm.releases",        ProbeFamily.CONTAINER),
        (K8sMeshMtls,            "k8s.mesh.mtls",            ProbeFamily.CONTAINER),
    ],
)
def test_metadata(cls, probe_id, family):
    p = cls()
    assert p.id == probe_id
    assert p.family is family


@pytest.mark.asyncio
async def test_runtime_detect_applies_only_when_runtime_present():
    p = ContainerRuntimeDetect()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    expected = any(shutil.which(b) for b in ("docker", "podman", "containerd",
                                              "nerdctl", "crictl"))
    assert (await p.applies(ctx)) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls",
    [K8sIngressTls, K8sSecretsTypes, K8sMeshMtls],
)
async def test_kubectl_probes_skip_without_capability(cls):
    p = cls()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    # No KUBECTL capability and no kubectl binary in tests → applies() False.
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_container_image_sbom_skips_without_capability():
    p = ContainerImageSbom()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_helm_skips_without_helm_binary():
    p = K8sHelmReleases()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    expected = shutil.which("helm") is not None
    assert (await p.applies(ctx)) is expected
