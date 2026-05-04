"""Tests for B10 app-config probes."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.app_dotenv_secrets import AppDotenvSecrets
from pqcscan.probes.app_jwt_env_alg import AppJwtEnvAlg
from pqcscan.probes.app_nginx_jwt_validation import AppNginxJwtValidation
from pqcscan.probes.app_oauth_jwks import AppOauthJwks
from pqcscan.probes.app_spring_properties import AppSpringProperties


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (AppJwtEnvAlg, "app.jwt.env_alg"),
        (AppOauthJwks, "app.oauth.jwks"),
        (AppDotenvSecrets, "app.dotenv.secrets"),
        (AppSpringProperties, "app.spring.properties"),
        (AppNginxJwtValidation, "app.nginx.jwt_validation"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.APP


@pytest.mark.asyncio
async def test_jwt_env_alg_flags_none(tmp_path: Path):
    env = tmp_path / "myapp" / ".env"
    env.parent.mkdir()
    env.write_text("JWT_ALG=none\nJWT_SECRET=hunter2\n")
    found: list = []
    p = AppJwtEnvAlg(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    # Both findings: 'none' alg + short secret.
    assert any(f.algorithm == "JWT-none" for f in found)
    assert any(f.algorithm == "JWT-SECRET-WEAK" for f in found)


@pytest.mark.asyncio
async def test_jwt_env_alg_flags_rs256(tmp_path: Path):
    # Use flat-property style — the regex doesn't bridge yaml parent/child
    # across newlines.
    cfg = tmp_path / "app" / "application.properties"
    cfg.parent.mkdir()
    cfg.write_text("jwt.algorithm=RS256\nserver.port=8080\n")
    found: list = []
    p = AppJwtEnvAlg(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    rs256 = [f for f in found if f.algorithm == "JWT-RS256"]
    assert rs256
    assert rs256[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_oauth_jwks_flags_rsa_2048(tmp_path: Path):
    # n with len ~340 chars -> ~2040 bits (typical 2048-bit modulus).
    n_value = "0" * 342
    jwks = tmp_path / "jwks.json"
    jwks.write_text(
        '{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":"' + n_value + '","e":"AQAB"}]}'
    )
    found: list = []
    p = AppOauthJwks(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm.startswith("RSA-")
               and f.classification in {Classification.SANGAT_TINGGI, Classification.TINGGI}
               for f in found)


@pytest.mark.asyncio
async def test_dotenv_secrets_flags_short_secret_key(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("DJANGO_SECRET_KEY=short\n")
    found: list = []
    p = AppDotenvSecrets(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("DJANGO_SECRET_KEY" in f.title for f in found)
    assert all(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_spring_properties_flags_tlsv1(tmp_path: Path):
    cfg = tmp_path / "application.properties"
    cfg.write_text(
        "server.port=8443\n"
        "server.ssl.enabled-protocols=TLSv1,TLSv1.2\n"
        "server.ssl.key-store-type=JKS\n"
    )
    found: list = []
    p = AppSpringProperties(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("TLSv1" in t and "TLSv1.2" not in t for t in titles)
    assert any("JKS" in t for t in titles)


@pytest.mark.asyncio
async def test_nginx_jwt_validation_flags_directives(tmp_path: Path):
    cfg = tmp_path / "site.conf"
    cfg.write_text(
        "server {\n"
        "  auth_jwt \"realm\" token=$cookie_token;\n"
        "  auth_jwt_alg HS256;\n"
        "}\n"
    )
    found: list = []
    p = AppNginxJwtValidation(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("auth_jwt_alg" in f.title for f in found)
