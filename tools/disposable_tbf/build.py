"""Build/assemble an explicitly disposable, diskless x86_64 TBF fixture. No sudo."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def unpack(archive, target):
    target.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        for member in source:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError("unsafe archive member")
            destination = target / path
            if not destination.resolve().is_relative_to(target.resolve()):
                raise ValueError("archive path escapes extraction root")
            if member.issym() and not (destination.parent / member.linkname).resolve().is_relative_to(target.resolve()):
                raise ValueError("archive link escapes extraction root")
            member.mode &= 0o777
            source.extract(member, target)


def fetch(asset, cache):
    path = cache / (asset["name"] + "-source.tar.gz")
    if path.exists():
        if path.is_symlink():
            raise ValueError("cache symlink refused")
        if path.stat().st_size != asset["bytes"] or sha(path) != asset["sha256"]:
            raise ValueError("cached archive commitment mismatch")
        return path
    fd, temporary = tempfile.mkstemp(prefix=asset["name"] + "-", suffix=".partial", dir=cache)
    os.close(fd)
    partial = Path(temporary)
    try:
        with urllib.request.urlopen(asset["url"], timeout=30) as response, partial.open("wb") as output:
            if not response.url.startswith(("https://codeload.github.com/", "https://registry.npmjs.org/")):
                raise ValueError("asset redirected outside fixed source hosts")
            count = 0
            while block := response.read(1024 * 1024):
                count += len(block)
                if count > asset["bytes"]:
                    raise ValueError("asset size budget")
                output.write(block)
        if partial.stat().st_size != asset["bytes"] or sha(partial) != asset["sha256"]:
            raise ValueError("download commitment mismatch")
        partial.rename(path)
    finally:
        partial.unlink(missing_ok=True)
    return path


def run(args, cwd, log, env=None, timeout=1200):
    with log.open("ab") as output:
        subprocess.run(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=timeout,
        )


def compatibility(root):
    """Old pinned bootstrap gnulib vs glibc >=2.28/2.34; never patch the guest kernel."""
    lib = root / "lib"
    for path in lib.glob("*.c"):
        text = path.read_text().replace("_IO_ftrylockfile", "_IO_EOF_SEEN")
        if "#ifndef SIGSTKSZ" in text:
            start = text.index("#ifndef SIGSTKSZ")
            end = text.index("#include <stdlib.h>", start)
            text = (text[:start] + text[end:]).replace("SIGSTKSZ", "65536")
        path.write_text(text)
    header = lib / "stdio-impl.h"
    if header.exists():
        header.write_text(header.read_text() + "\n#ifndef _IO_IN_BACKUP\n#define _IO_IN_BACKUP 0x100\n#endif\n")


def harden_musl_signals(root):
    # musl 1.2.5 uses tkill for pthread signals. Constrain them to this process's
    # TGID so the launcher can keep tkill and cross-process signaling denied.
    names = ("src/thread/pthread_kill.c", "src/thread/pthread_cancel.c", "src/thread/synccall.c", "src/signal/raise.c")
    for name in names:
        path = root / name
        text = path.read_text()
        if text.count("SYS_tkill,") != 1:
            raise ValueError("unexpected pinned musl signal source")
        path.write_text(text.replace("SYS_tkill,", "SYS_tgkill, __syscall(SYS_getpid),"))


def build(cache, work, output):
    if os.geteuid() == 0 or os.uname().machine != "x86_64":
        raise ValueError("ordinary-user x86_64 Linux build required")
    cache.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=False)
    lock = json.loads((HERE / "assets.lock.json").read_text())
    roots = {}
    for asset in lock["assets"]:
        archive = fetch(asset, cache)
        parent = work / asset["name"]
        unpack(archive, parent)
        roots[asset["name"]] = parent / asset["top_directory"]
    prefix = work / "build-tools"
    env = {
        "PATH": str(prefix / "bin") + ":/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": str(work),
        "SOURCE_DATE_EPOCH": "1761868800",
    }
    for name in ("m4", "bison", "flex"):
        root = roots[name]
        compatibility(root)
        log = work / (name + ".log")
        run(["./configure", "--prefix=" + str(prefix), "--disable-nls"], root, log, env)
        run(["make", "-j2"], root, log, env)
        run(["make", "install"], root, log, env)
    (prefix / "bin/bc").symlink_to("/usr/bin/busybox")  # fixed BusyBox bc applet; no extra download
    (prefix / "include").mkdir(exist_ok=True)
    (prefix / "lib").mkdir(exist_ok=True)
    for name in ("libelf.h", "gelf.h"):
        shutil.copy2(roots["elfutils"] / "libelf" / name, prefix / "include" / name)
    (prefix / "lib/libelf.so").symlink_to("/lib/x86_64-linux-gnu/libelf.so.1")
    env.update(
        C_INCLUDE_PATH=str(prefix / "include"),
        LIBRARY_PATH=str(prefix / "lib"),
        KCONFIG_ALLCONFIG=str(HERE / "kernel.config"),
        KBUILD_BUILD_USER="cryptoscan",
        KBUILD_BUILD_HOST="disposable",
        KBUILD_BUILD_TIMESTAMP="2025-10-31 00:00:00 UTC",
    )
    run(["make", "allnoconfig"], roots["linux"], work / "kernel.log", env)
    run(["make", "-j2", "bzImage"], roots["linux"], work / "kernel.log", env)
    harden_musl_signals(roots["musl"])
    runtime = work / "musl-runtime"
    run(
        ["./configure", "--prefix=" + str(runtime), "--syslibdir=" + str(runtime / "lib")],
        roots["musl"],
        work / "musl.log",
        env,
    )
    run(["make", "-j2"], roots["musl"], work / "musl.log", env)
    run(["make", "install"], roots["musl"], work / "musl.log", env)
    return assemble(
        output,
        roots["linux"] / "arch/x86/boot/bzImage",
        roots["linux"] / ".config",
        roots["qemu"],
        runtime / "lib/libc.so",
    )


def copy_elf(source, target, root):
    """Only fixed trusted system tools and their loader-resolved ordinary shared libraries."""
    source = Path(source)
    info = source.stat()
    if info.st_uid != 0 or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID) or not source.is_file():
        raise ValueError("untrusted host runtime input")
    destination = root / str(target).lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    value = subprocess.run(
        ["/usr/bin/ldd", str(source)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=10,
    )
    if value.returncode:
        if "not a dynamic executable" in value.stdout + value.stderr:
            return
        raise ValueError("unsupported runtime linkage")
    for line in value.stdout.splitlines():
        if "not found" in line:
            raise ValueError("missing runtime library")
        for token in line.split():
            if token.startswith("/"):
                library = Path(token)
                if not str(library).startswith(("/lib/", "/lib64/", "/usr/lib/")):
                    raise ValueError("unexpected library prefix")
                info = library.stat()
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError("untrusted runtime library")
                dest = root / str(library).lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, dest)


def initramfs(root, output):
    """Deterministic newc, only regular files/directories; no privileged cpio/mount."""
    with output.open("xb") as target, gzip.GzipFile(filename="", fileobj=target, mode="wb", mtime=0) as archive:

        def entry(name, mode, data, inode, rmajor=0, rminor=0):
            encoded = name.encode() + b"\0"
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, rmajor, rminor, len(encoded), 0]
            header = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
            archive.write(header + encoded)
            archive.write(b"\0" * (-(len(header) + len(encoded)) % 4))
            archive.write(data)
            archive.write(b"\0" * (-len(data) % 4))

        for inode, path in enumerate(sorted(root.rglob("*")), 1):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError("unexpected initramfs node")
            mode = stat.S_IFDIR | 0o755 if path.is_dir() else stat.S_IFREG | (path.stat().st_mode & 0o777)
            entry(str(path.relative_to(root)), mode, path.read_bytes() if path.is_file() else b"", inode)
        entry("dev/console", stat.S_IFCHR | 0o600, b"", 100000, 5, 1)
        entry("dev/null", stat.S_IFCHR | 0o666, b"", 100001, 1, 3)
        entry("TRAILER!!!", 0, b"", 0)


def assemble(output, kernel, config, qemu_root, loader):
    """Also permits an operator's prebuilt matching kernel; all resulting bytes are pinned."""
    config_text = config.read_text()
    for required in ("CONFIG_NET_SCH_TBF=y", "CONFIG_INET=y", "CONFIG_BLK_DEV_INITRD=y"):
        if required not in config_text.splitlines():
            raise ValueError("required built-in guest capability missing")
    if "CONFIG_MODULES=y" in config_text.splitlines():
        raise ValueError("module-free fixture required")
    output.mkdir(parents=True, exist_ok=False)
    root = output / "rootfs"
    root.mkdir()
    for name in ("dev", "proc", "sys", "tmp", "bin", "sbin", "usr/lib/python3.11/lib-dynload"):
        (root / name).mkdir(parents=True, exist_ok=True)
    for source, dest in (
        ("/usr/bin/busybox", "/bin/busybox"),
        ("/usr/bin/python3.11", "/bin/python3.11"),
        ("/usr/bin/ip", "/sbin/ip"),
        ("/usr/sbin/tc", "/sbin/tc"),
    ):
        copy_elf(source, dest, root)
    stdlib = Path("/usr/lib/python3.11")
    for path in sorted(stdlib.rglob("*.py")):
        if (
            "__pycache__" in path.parts
            or "dist-packages" in path.parts
            or path.is_symlink()
            or path.name == "sitecustomize.py"
        ):
            continue
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted Python standard library")
        dest = root / str(path).lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    # Debian's fixed Python has needed C modules built in. No site packages, host app or credentials copied.
    shutil.copy2(HERE / "guest.py", root / "guest.py")
    (root / "DISPOSABLE_TBF_VM").write_text("Owned diskless engineering fixture only\n")
    init = root / "init"
    init.write_text(
        "#!/bin/busybox sh\n/bin/busybox mount -t devtmpfs devtmpfs /dev\n"
        "/bin/busybox mount -t proc proc /proc\n/bin/busybox mount -t sysfs sysfs /sys\n"
        "/bin/python3.11 -I -S /guest.py\n/bin/busybox reboot -f\n"
    )
    init.chmod(0o755)
    run(
        [
            "/usr/bin/gcc",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(HERE / "probe.c"),
            "-o",
            str(root / "probe"),
        ],
        HERE,
        output / "probe-build.log",
    )
    initramfs(root, output / "initramfs.cpio.gz")
    shutil.copy2(kernel, output / "kernel")
    shutil.copy2(config, output / "kernel.config")
    emulator = output / "emulator"
    emulator.mkdir()
    shutil.copy2(loader, emulator / "libc.so")
    shutil.copy2(qemu_root / "bin/qemu-system-x86_64", emulator / "qemu")
    shutil.copytree(qemu_root / "lib", emulator / "lib")
    shutil.copytree(qemu_root / "share", emulator / "share")
    run(
        [
            "/usr/bin/gcc",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(HERE / "sandbox.c"),
            "-o",
            str(output / "launcher"),
        ],
        HERE,
        output / "launcher-build.log",
    )
    manifest = {
        "schema_version": "cryptoscan.disposable-tbf-bundle/v1",
        "profile": "DISKLESS_TCG_NO_NIC_V1",
        "source_authenticity_verified": False,
        "assets_lock_sha256": sha(HERE / "assets.lock.json"),
        "guest_source_sha256": sha(HERE / "guest.py"),
        "probe_source_sha256": sha(HERE / "probe.c"),
        "launcher_source_sha256": sha(HERE / "sandbox.c"),
        "builder_source_sha256": sha(HERE / "build.py"),
        "kernel_profile_sha256": sha(HERE / "kernel.config"),
        "guest_runtime_files": [
            {"path": str(p.relative_to(root)), "sha256": sha(p), "bytes": p.stat().st_size}
            for p in sorted(root.rglob("*"))
            if p.is_file()
        ],
        "files": [],
    }
    for path in sorted(output.rglob("*")):
        if path.is_file() and not path.is_relative_to(root):
            manifest["files"].append(
                {"path": str(path.relative_to(output)), "sha256": sha(path), "bytes": path.stat().st_size}
            )
    # Retain only boot inputs, not a writable rootfs tree.
    shutil.rmtree(root)
    (output / "bundle.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return sha(output / "bundle.json")
