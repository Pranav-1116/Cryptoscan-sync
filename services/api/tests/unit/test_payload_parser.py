from api.github.payload_parser import parse_push_event


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
