from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.schemas.account import AccountCreate
from app.schemas.category import CategoryCreate
from app.schemas.client import ClientCreate
from app.schemas.tag import TagCreate
from app.services.account_service import AccountService
from app.services.category_service import CategoryService, ClientService
from app.services.tag_service import TagService


@dataclass
class SeededWorkspace:
    categories: dict[str, Any]
    clients: dict[str, Any]
    tags: dict[str, Any]
    accounts: dict[str, Any]


DEMO_CATEGORIES = [
    {"name": "Infrastructure", "description": "Servers, networks, and platform services"},
    {"name": "SaaS", "description": "Cloud applications and vendor portals"},
    {"name": "Databases", "description": "Database users and administrative access"},
    {"name": "Network", "description": "Routers, switches, firewalls, and VPNs"},
    {"name": "DevOps", "description": "CI/CD pipelines, registries, and tooling"},
]

DEMO_CLIENTS = [
    {"name": "Acme Corp", "notes": "Primary demo customer", "is_global": True},
    {"name": "Internal IT", "notes": "Internal operations team", "is_global": True},
    {"name": "Contoso Labs", "notes": "Sandbox and QA systems", "is_global": True},
    {"name": "Globex Inc", "notes": "Secondary enterprise customer", "is_global": True},
    {"name": "DevOps Team", "notes": "Platform engineering group", "is_global": True},
]

DEMO_TAGS = [
    {"name": "production", "color": "#b91c1c"},
    {"name": "staging", "color": "#d97706"},
    {"name": "shared", "color": "#2563eb"},
    {"name": "rotation-required", "color": "#7c3aed"},
    {"name": "linux", "color": "#059669"},
    {"name": "windows", "color": "#0284c7"},
    {"name": "cloud", "color": "#0891b2"},
]

# Representative subset of the archived PHP demo seed, rewritten for the
# Python service layer so tests can create a realistic workspace quickly.
DEMO_ACCOUNTS = [
    {
        "title": "Acme VPN Gateway",
        "client": "Acme Corp",
        "category": "Network",
        "login": "vpn-admin",
        "url": "https://vpn.acme.example",
        "password": "ExampleVPN!2026",
        "notes": "Demo VPN account created from the archived seed example.",
        "tags": ["production", "rotation-required"],
    },
    {
        "title": "Acme GitHub Org",
        "client": "Acme Corp",
        "category": "DevOps",
        "login": "acme-bot",
        "url": "https://github.com/acme-corp",
        "password": "ghp_AcmeExampleToken2026",
        "notes": "Machine user PAT for CI automation",
        "tags": ["production", "rotation-required"],
    },
    {
        "title": "Internal MySQL Root",
        "client": "Internal IT",
        "category": "Databases",
        "login": "root",
        "url": "mysql://db.internal.example:3306",
        "password": "ExampleDbRoot!2026",
        "notes": "Demo database credential. Rotate before using real data.",
        "tags": ["production", "rotation-required"],
    },
    {
        "title": "Internal AD Administrator",
        "client": "Internal IT",
        "category": "Infrastructure",
        "login": "Administrator",
        "url": "ldap://dc.internal.example",
        "password": "IntAdm!n2026",
        "notes": "Active Directory domain administrator",
        "tags": ["production", "windows", "rotation-required"],
    },
    {
        "title": "Contoso Jenkins",
        "client": "Contoso Labs",
        "category": "DevOps",
        "login": "admin",
        "url": "http://jenkins.contoso.example:8080",
        "password": "Cnts0Jnk!2026",
        "notes": "Jenkins CI - QA pipeline",
        "tags": ["staging", "shared"],
    },
    {
        "title": "Globex Oracle DB",
        "client": "Globex Inc",
        "category": "Databases",
        "login": "system",
        "url": "oracle://ora1.globex.example:1521/ORCL",
        "password": "Gl0b3xOra!2026",
        "notes": "Oracle 19c - ERP backend",
        "tags": ["production", "rotation-required"],
    },
    {
        "title": "Kubernetes Cluster Admin",
        "client": "DevOps Team",
        "category": "DevOps",
        "login": "k8s-admin",
        "url": "https://k8s.devops.example:6443",
        "password": "D3v0ps!K8s2026",
        "notes": "kubeconfig for production cluster",
        "tags": ["production", "rotation-required"],
    },
    {
        "title": "Grafana Admin",
        "client": "DevOps Team",
        "category": "SaaS",
        "login": "admin",
        "url": "https://grafana.devops.example",
        "password": "D3v0ps!Grfn26",
        "notes": "Grafana - metrics and observability dashboards",
        "tags": ["production", "shared"],
    },
]


def seed_demo_workspace(db, encryption_service, owner_user) -> SeededWorkspace:
    category_service = CategoryService(db)
    client_service = ClientService(db)
    tag_service = TagService(db)
    account_service = AccountService(db, encryption_service)

    categories = {
        item["name"]: category_service.create_category(CategoryCreate(**item))
        for item in DEMO_CATEGORIES
    }
    clients = {
        item["name"]: client_service.create_client(ClientCreate(**item))
        for item in DEMO_CLIENTS
    }
    tags = {
        item["name"]: tag_service.create_tag(TagCreate(**item), owner_user.id)
        for item in DEMO_TAGS
    }

    accounts: dict[str, Any] = {}
    for item in DEMO_ACCOUNTS:
        account = account_service.create_account(
            AccountCreate(
                title=item["title"],
                login=item["login"],
                password=item["password"],
                url=item["url"],
                notes=item["notes"],
                category_id=categories[item["category"]].id,
                client_id=clients[item["client"]].id,
                tag_ids=[tags[tag_name].id for tag_name in item["tags"]],
            ),
            owner_user.id,
        )
        accounts[item["title"]] = account

    return SeededWorkspace(
        categories=categories,
        clients=clients,
        tags=tags,
        accounts=accounts,
    )
