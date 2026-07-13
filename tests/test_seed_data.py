from tests.seed_data import seed_demo_workspace


def test_seed_demo_workspace_creates_realistic_fixture_set(db_session, encryption_service, test_user):
    workspace = seed_demo_workspace(db_session, encryption_service, test_user)

    assert len(workspace.categories) == 5
    assert len(workspace.clients) == 5
    assert len(workspace.tags) == 7
    assert len(workspace.accounts) == 8

    vpn = workspace.accounts["Acme VPN Gateway"]
    jenkins = workspace.accounts["Contoso Jenkins"]
    grafana = workspace.accounts["Grafana Admin"]

    assert vpn.category_id == workspace.categories["Network"].id
    assert vpn.client_id == workspace.clients["Acme Corp"].id
    assert jenkins.client_id == workspace.clients["Contoso Labs"].id
    assert grafana.category_id == workspace.categories["SaaS"].id

    production_tag_ids = {tag.id for tag in workspace.tags.values() if tag.name == "production"}
    shared_tag_ids = {tag.id for tag in workspace.tags.values() if tag.name == "shared"}

    assert any(tag.id in production_tag_ids for tag in vpn.tags)
    assert any(tag.id in shared_tag_ids for tag in grafana.tags)
