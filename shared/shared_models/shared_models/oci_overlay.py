"""Pure OCI overlay planning: whiteouts affect lower layers, never same-layer files."""

WHITEOUT_PREFIX = ".wh."
OPAQUE = ".wh..wh..opq"


def overlay(lower, current, whiteouts, opaque):
    """Entries are inert metadata, not host paths. Caller validates archive members."""
    result = dict(lower)
    for path in [*whiteouts, *opaque]:
        parts = path.split("/")
        for n in range(1, len(parts)):
            ancestor = "/".join(parts[:n])
            if any(ancestor in tree and tree[ancestor]["type"] != "dir" for tree in (lower, current)):
                raise ValueError("Whiteout through non-directory ancestor")
        if path in opaque and path in lower and lower[path]["type"] != "dir":
            raise ValueError("Opaque whiteout on non-directory")
    # Apply all removals before additions regardless of tar/directory ordering.
    for victim in whiteouts:
        for path in list(result):
            if path == victim or path.startswith(victim + "/"):
                del result[path]
    for directory in opaque:
        for path in list(result):
            if path.startswith(directory + "/") if directory else bool(path):
                del result[path]
    for path, value in sorted(current.items(), key=lambda kv: (kv[0].count("/"), kv[0])):
        parts = path.split("/")
        for n in range(1, len(parts)):
            ancestor = "/".join(parts[:n])
            # Do not resolve writes through links inherited from lower layers.
            if ancestor in result and result[ancestor]["type"] != "dir":
                raise ValueError("Layer writes through non-directory ancestor")
        if value["type"] != "dir":
            for old in list(result):
                if old.startswith(path + "/"):
                    del result[old]
        result[path] = value
    return result


def resolve(view, path):
    """Resolve image-internal links only; never consult the host filesystem."""
    seen = set()
    for _ in range(32):
        if path in seen:
            raise ValueError("Cyclic image link")
        seen.add(path)
        parts = path.split("/")
        changed = False
        for n in range(1, len(parts) + 1):
            prefix = "/".join(parts[:n])
            entry = view.get(prefix)
            if entry and entry["type"] == "symlink":
                path = "/".join([entry["target"], *parts[n:]])
                changed = True
                break
            if entry and n < len(parts) and entry["type"] != "dir":
                raise ValueError("Database ancestor is not a directory")
        if not changed:
            return path, view.get(path)
    raise ValueError("Image link resolution limit")
