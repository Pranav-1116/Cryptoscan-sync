"""Dashboard-only container: mount public input ONLY. No bank protocols/scanner."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial
from pathlib import Path
from urllib.parse import unquote, urlsplit


class PublicOnly(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        rel = unquote(urlsplit(path).path).lstrip("/") or "index.html"
        root = Path(self.directory).resolve()
        candidate = root / rel
        if ".." in Path(rel).parts or candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return str(root / "FORBIDDEN-NONEXISTENT")
        return str(candidate)

    def list_directory(self, path):
        self.send_error(403, "Directory listing disabled")
        return None

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), partial(PublicOnly, directory="/public")).serve_forever()
