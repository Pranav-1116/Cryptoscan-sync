from worker.workspace.workspace_manager import WorkspaceManager


def test_create_and_cleanup(tmp_path):
    mgr = WorkspaceManager(str(tmp_path))
    path = mgr.create("abc")
    assert path.exists()
    (path / "x.txt").write_text("ok")
    mgr.cleanup(path)
    assert not path.exists()


def test_cleanup_removes_workspace_created_under_relative_base(tmp_path, monkeypatch):
    """Regression: relative base + create() path was never cleaned (soak finding)."""
    from worker.workspace.workspace_manager import WorkspaceManager

    monkeypatch.chdir(tmp_path)
    mgr = WorkspaceManager("./data/workspaces")
    ws = mgr.create("job-rel")
    (ws / "repo").mkdir()
    (ws / "repo" / "f.py").write_text("x")
    assert not ws.is_absolute()
    mgr.cleanup(ws)
    assert not ws.exists()


def test_cleanup_still_refuses_paths_outside_base(tmp_path):
    from worker.workspace.workspace_manager import WorkspaceManager

    mgr = WorkspaceManager(str(tmp_path / "ws"))
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    mgr.cleanup(outside)
    assert outside.exists()
