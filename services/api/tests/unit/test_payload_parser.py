from api.github.payload_parser import parse_pull_request_event, parse_push_event


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
