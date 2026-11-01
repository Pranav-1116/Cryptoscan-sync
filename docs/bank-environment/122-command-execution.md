# Command execution — can collector input become a command?

`cryptoscan.command-execution/1` · generated 2026-11-01T04:30:22.317182+00:00 · **4 pass · 0 partial · 0 fail** · 91 process call sites

| Question | Verdict | Evidence |
|---|---|---|
| **does any collector input reach a shell?** | **PASS** | 0 shell sink(s); 0 string command(s); 91 argv-list call(s) in 50 module(s) |
| **can a hostile target become an option or a second argument?** | **PASS** | 3 call site(s) driven with 6 hostile inputs each; 0 site(s) failed |
| **is `--` used before every untrusted positional?** | **PASS** | 2 of 91 call sites take a caller-supplied positional; 2 pass `--` before it |
| **does the branch touch the docker socket, exec into pods, or run as root?** | **PASS** | docker socket 0 · pod exec 0 · setuid(0) 0 |

## Row by row

### `shell_sinks` — PASS

*does any collector input reach a shell?*

- **PASS** `no-shell` — 0 shell sink(s); 0 string command(s); 91 argv-list call(s) in 50 module(s)
- **Limit:** a census reads source; a call site reached through an import alias or a compiled extension would be invisible to it

### `argument_injection` — PASS

*can a hostile target become an option or a second argument?*

- **PASS** `hostile-inputs-contained` — 3 call site(s) driven with 6 hostile inputs each; 0 site(s) failed
- **PASS** `control-vulnerable-sink` — a shell string reached subprocess, so the check reports a failure

#### `ssh_keyscan` — PASS (`host`)

- PASS `ssh_keyscan:option:-oProxyCommand=tou`: no process was spawned — the input never reached a command
- PASS `ssh_keyscan:semicolon:example.com; touch`: no process was spawned — the input never reached a command
- PASS `ssh_keyscan:subshell:example.com$(touch`: no process was spawned — the input never reached a command
- PASS `ssh_keyscan:backtick:example.com`touch `: no process was spawned — the input never reached a command
- PASS `ssh_keyscan:newline:example.com
touch `: no process was spawned — the input never reached a command
- PASS `ssh_keyscan:pipe:example.com | touc`: no process was spawned — the input never reached a command
- PASS `control-legitimate-value`: passed as a single argv element (ssh-keyscan …)

#### `git_clone` — PASS (`repo_url`)

- PASS `git_clone:option:-oProxyCommand=tou`: refused with ValueError
- PASS `git_clone:semicolon:example.com; touch`: refused with ValueError
- PASS `git_clone:subshell:example.com$(touch`: refused with ValueError
- PASS `git_clone:backtick:example.com`touch `: refused with ValueError
- PASS `git_clone:newline:example.com
touch `: refused with ValueError
- PASS `git_clone:pipe:example.com | touc`: refused with ValueError
- PASS `control-legitimate-value`: refused with RuntimeError

#### `image_reference` — PASS (`reference`)

- PASS `image_reference:option:-oProxyCommand=tou`: refused with ValueError
- PASS `image_reference:semicolon:example.com; touch`: refused with ValueError
- PASS `image_reference:subshell:example.com$(touch`: refused with ValueError
- PASS `image_reference:backtick:example.com`touch `: refused with ValueError
- PASS `image_reference:newline:example.com
touch `: refused with ValueError
- PASS `image_reference:pipe:example.com | touc`: refused with ValueError
- PASS `control-legitimate-value`: no process was spawned — the input never reached a command
- **Limit:** the canary proves an input did not execute through *this* call site; it cannot prove the same input does not reach another sink later in the pipeline
- **Limit:** the recorder replaces subprocess, so a site that shells out through a library (paramiko, docker-py) would not appear here

### `end_of_options` — PASS

*is `--` used before every untrusted positional?*

- **PASS** `untrusted-positional-terminated` — 2 of 91 call sites take a caller-supplied positional; 2 pass `--` before it
- **PASS** `every-driven-site-classified` — 2 driven site(s) pass their parameter straight to a spawn call; 1 build the argv one function up (image_reference) and all terminate it
- **PASS** `control-plan-positional` — 89 call sites pass only fixed flags or validated values and are excluded by construction
- **Limit:** Some CLIs take their target as an *option's value* (`openssl s_client -connect`, `ssh -o`, `git -C`) rather than a positional: there `--` does nothing and the grammar check is the whole defence. Those sites are covered by the argument-injection row, not by this one.

### `privileged_surfaces` — PASS

*does the branch touch the docker socket, exec into pods, or run as root?*

- **PASS** `no-privileged-exec` — docker socket 0 · pod exec 0 · setuid(0) 0
- **Not proven:** the container scanner reads images through skopeo/docker/podman CLIs; if a deployment mounts the socket, the CLI inherits that authority and this source census would not see it
- **Not proven:** seccomp and namespace isolation of the static scanner are not measured here

## What this does not prove

- Source census plus executed probes in-process. No real `ssh-keyscan`, `git` or container CLI was asked to run: the recorder stands in for subprocess, so this proves what would have been passed to them, not what they did with it.
- Shell expansion inside a spawned tool (a tool that itself calls a shell) is out of scope — the tool's own argument handling is the boundary.

**The verdict this drill supports:** no collector input reaches a shell, and every call site that takes a target either refuses a hostile one or passes it as a single argv element — with `--` before the positional wherever the tool supports it. The gap that remains is the deployment: a mounted docker socket, a privileged container or a tool that expands its own arguments is outside what a source census can see.
