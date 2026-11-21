"""REST API tests against the offline demo dataset (no network)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("WAPTRIX_DB", str(tmp_path / "api.db"))
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_health_and_metadata(client):
    assert client.get("/api/health").json()["mode"] == "passive"
    assert len(client.get("/api/owasp").json()) == 10
    rules = client.get("/api/rules").json()
    assert any(r["id"] == "HDR-CSP-MISSING" and r["cvss_score"] > 0 for r in rules)
    assert all(r["method"] and r["module_name"] for r in rules)
    assert all(c["manual_tests"] for c in client.get("/api/owasp").json())


def test_demo_roundtrip_and_exports(client):
    demo = client.post("/api/demo").json()
    assert demo["demo"] is True and len(demo["subdomains"]) == 5

    listed = client.get("/api/audits").json()
    assert listed[0]["id"] == demo["id"]

    detail = client.get(f"/api/audits/{demo['id']}/subdomains/admin.acme-corp.example").json()
    assert detail["grade"] == "F"

    sarif = client.get(f"/api/audits/{demo['id']}/export", params={"format": "sarif"})
    assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
    assert "attachment" in sarif.headers["content-disposition"]

    csv_resp = client.get(f"/api/audits/{demo['id']}/export",
                          params={"format": "csv", "subdomain": "www.acme-corp.example"})
    body = csv_resp.content.decode("utf-8-sig").splitlines()
    assert all("www.acme-corp.example" in line for line in body[1:])

    assert client.get(f"/api/audits/{demo['id']}/export", params={"format": "docx"}).status_code == 400
    assert client.get(f"/api/audits/{demo['id']}/export", params={"subdomain": "nope.example"}).status_code == 400

    assert client.delete(f"/api/audits/{demo['id']}").status_code == 204
    assert client.get(f"/api/audits/{demo['id']}").status_code == 404


def test_audit_creation_enforces_scope(client):
    missing_ref = client.post("/api/audits", json={"subdomains": ["app.example.com"], "authorization_ref": ""})
    assert missing_ref.status_code == 422
    only_wildcards = client.post("/api/audits", json={"subdomains": ["*.example.com"], "authorization_ref": "ENG-1"})
    assert only_wildcards.status_code == 422
    too_fast = client.post("/api/audits", json={"subdomains": ["a.example.com"], "authorization_ref": "ENG-1",
                                                "requests_per_second": 500})
    assert too_fast.status_code == 422


def test_api_sets_security_headers(client):
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
