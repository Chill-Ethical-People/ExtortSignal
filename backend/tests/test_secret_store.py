import stat

from ransom_monitor.ai_providers import provider_by_id, provider_catalog
from ransom_monitor.secret_store import SecretStore


def test_secret_store_persists_with_user_only_permissions(tmp_path):
    path = tmp_path / "data" / "secrets.json"
    store = SecretStore(path)

    store.set("DEEPSEEK_API_KEY", "test-secret-value")

    assert store.get("DEEPSEEK_API_KEY") == "test-secret-value"
    assert store.configured_names() == {"DEEPSEEK_API_KEY"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    store.delete("DEEPSEEK_API_KEY")
    assert store.get("DEEPSEEK_API_KEY") == ""
    assert store.configured_names() == set()


def test_provider_catalog_reports_local_credential_without_exposing_it(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    provider = next(
        item
        for item in provider_catalog({"DEEPSEEK_API_KEY"})
        if item["id"] == "deepseek"
    )

    assert provider["credential_configured"] is True
    assert provider["credential_source"] == "local_store"
    assert "test-secret-value" not in str(provider)


def test_kimi_and_glm_provider_defaults_are_available():
    kimi = provider_by_id("kimi")
    glm = provider_by_id("zhipu")

    assert kimi is not None
    assert kimi["base_url"] == "https://api.moonshot.ai/v1"
    assert kimi["models"][:2] == ["kimi-k3", "kimi-k2.6"]
    assert kimi["api_key_env"] == "MOONSHOT_API_KEY"

    assert glm is not None
    assert glm["name"] == "GLM (Zhipu BigModel)"
    assert glm["base_url"] == "https://open.bigmodel.cn/api/paas/v4"
    assert "glm-5-turbo" in glm["models"]
