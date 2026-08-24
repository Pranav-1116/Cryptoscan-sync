from api.github.status_poster import parse_github_repo, post_pipeline_status


def test_parse_github_repo():
    assert parse_github_repo("https://github.com/acme/payments-api.git") == ("acme", "payments-api")
    assert parse_github_repo("git@github.com:acme/payments-api.git") == ("acme", "payments-api")
    assert parse_github_repo("local://demo/app") is None


def test_post_pipeline_status_noop_without_token():
    assert post_pipeline_status(
        token="",
        repo_url="https://github.com/acme/payments-api",
        commit="abc",
        state="success",
        description="ok",
    ) is False
