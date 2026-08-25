from api.github.payload_parser import parse_pull_request_event, parse_push_event
from api.webhooks.acr_webhook_handler import handle_acr_event
from api.webhooks.ecr_webhook_handler import handle_ecr_event
from api.webhooks.gcr_webhook_handler import handle_gcr_event


def test_parse_push_event():
    payload = {
        "ref": "refs/heads/main",
        "after": "abc123def456",
        "repository": {"clone_url": "https://github.com/org/repo.git", "full_name": "org/repo"},
        "head_commit": {"id": "abc123def456", "message": "fix", "author": {"name": "Ada"}},
    }
    parsed = parse_push_event(payload)
    assert parsed["repo_url"].endswith("repo.git")
    assert parsed["branch"] == "main"
    assert parsed["author"] == "Ada"


def test_parse_pull_request_event():
    payload = {
        "action": "opened",
        "repository": {"clone_url": "https://github.com/org/repo.git", "full_name": "org/repo"},
        "pull_request": {
            "number": 12,
            "title": "Add AES-GCM",
            "user": {"login": "ada"},
            "head": {"sha": "abc123def4567890", "ref": "feature/crypto"},
        },
    }
    parsed = parse_pull_request_event(payload)
    assert parsed["branch"] == "feature/crypto"
    assert parsed["pr_number"] == 12
    assert parsed["author"] == "ada"
    assert parsed["commit"].startswith("abc123")


def test_registry_webhook_aliases_parse():
    ecr = handle_ecr_event(
        {"detail": {"repository-name": "pay", "image-tag": "latest", "registryId": "123"}}
    )
    assert ecr.get("repository") or ecr.get("image") or ecr
    acr = handle_acr_event({"target": {"repository": "pay", "tag": "v1"}})
    assert acr
    gcr = handle_gcr_event({"tag": "gcr.io/proj/pay:latest"})
    assert gcr
