# Apple Mail MCP

This standalone macOS CLI embeds CPython in its native `apple-mail-mcp`
process. Grant Full Disk Access directly to the installed **apple-mail-mcp**
executable in System Settings → Privacy & Security → Full Disk Access.
Use the add button and Command-Shift-G to select its absolute installed
path. Its embedded metadata names it **Apple Mail MCP**, with identifier
`com.tonyxiao.apple-mail-mcp`. There is no `.app` bundle. The CLI never launches a general Python
interpreter to read mail; its native executable remains the process that
opens the Mail database.

## Build

Install the mail package and its pinned dependencies into a real
site-packages directory, then build with the same Python runtime:

```sh
python3 macos-helper/build.py \
  --python /absolute/path/to/python3 \
  --site-packages /absolute/path/to/site-packages \
  --output /absolute/path/to/apple-mail-mcp
```

The output must not already exist. The builder queries `sysconfig` with
isolated Python, links the selected framework or shared library, and embeds
absolute paths for its standard library, dynamic extensions, and installed
dependencies. Editable `.pth` installs are not supported. `CC`, `SDKROOT`,
and a `codesign` executable on `PATH` are supported for Brew and Nix builds;
the signing fallback is `/usr/bin/codesign`.

The output is a signed native executable file. `Info.plist` metadata is
embedded in Mach-O `__TEXT,__info_plist`; no GUI bundle is created. Its Python
`sys.executable` and program name point to that native executable. Python
uses isolated configuration with environment processing, site initialization,
user packages, `.pth` hooks, and bytecode writes disabled. Import paths never
include the current working directory. `PYTHONPATH`, `PYTHONHOME`, startup
files, and inspection flags do not influence the runtime.

## Fixed modes

| Invocation | Behavior |
| --- | --- |
| No arguments / `http` | Authenticated HTTP on `127.0.0.1:58435`, `/mcp` and `/healthz` |
| `--fts` / `fts --sync --limit 2000` | FTS synchronization with a fixed batch limit of 2000 |
| `serve` / `--stdio` | Existing MCP stdio service, default backend name `apple-mail` |
| `sql query …` / `sql schema …` | Existing guarded, read-only SQL CLI; `--sql` alias accepted |
| `help` / `--help` | Show the supported CLI modes |
| `version` / `--version` | Print the installed mail package version |

Additional arguments to `--fts` or `--stdio` are refused. SQL arguments are
parsed by the existing SQL CLI; only the `query` and `schema` subcommands
are accepted. The CLI has no arbitrary Python code, script, module, or
general CLI entry point. HTTP and stdio retain all 23 tools; the existing
read-only mode configuration remains available.

## Service configuration

The CLI first checks `$HOME/.config/apple-mail-mcp/service.env`, then
`$HOME/.homebrew/services/apple-mail-mcp.env` if the first file is absent.
Set `APPLE_MAIL_MCP_ENV_FILE` to an absolute path for a different file, such
as `$HOME/.config/apple-mail-mcp/service.env` on Nix. An explicit missing
file is refused. Configuration files must be regular files owned by the
service user, with mode `0600` or `0400`; symlinks are refused. The maximum
file size is 64 KiB. Each line is one `KEY=value` assignment. Shell quoting
and comments are accepted as data; no shell, expansion, or code evaluation
runs. Unknown or duplicate keys are refused.

Supported keys are `APPLE_MAIL_MCP_NAME`, `APPLE_MAIL_MCP_ORIGIN`,
`APPLE_MAIL_MCP_HUB_ORIGIN`, `APPLE_MAIL_MCP_TOKEN_FILE`,
`APPLE_MAIL_MCP_HOST`, `APPLE_MAIL_MCP_PORT`, `EMAIL_MCP_STATE_DIR`,
`EMAIL_MCP_MAIL_DIR`, and `EMAIL_MCP_READ_ONLY`. Without a configuration
file these values may be declared in the service environment. File values
take precedence. For HTTP:

- `NAME` must be `apple-mail-tx-m5` or `apple-mail-cs-mini`.
- `ORIGIN` must be an exact HTTPS origin. `HUB_ORIGIN` defaults to
  `https://mcphub.meteor-ruffe.ts.net` and has the same validation.
- `TOKEN_FILE` must be absolute; the HTTP adapter additionally checks token
  ownership, private permissions, and token length without logging it.
- Optional `HOST` and `PORT` must equal the fixed bind values above.

All names in that list use the full `APPLE_MAIL_MCP_` prefix. Mail/state
directory overrides must be absolute. Keep credentials and mutable indexes
outside the executable and package. Reverse proxies must preserve Authorization
and send Host `127.0.0.1:58435`.

## Signing and trust boundary

The executable is ad-hoc signed with hardened runtime enabled. It carries only
`com.apple.security.cs.disable-library-validation`, necessary because the
ad-hoc CPython runtime and native wheel extensions have no common Apple
Team ID. It does **not** enable the DYLD environment entitlement; an
injected-dylib regression test verifies that dynamic loader environment
variables cannot execute a constructor before the helper starts.

Ad-hoc signing produces a designated requirement based on the executable's
code hash. Rebuilding or upgrading the helper/runtime can change its TCC
identity. After updates, remove the old FDA entry and add the installed executable
again if background SQL probes report permission failures. Restart the
helper after changing an FDA grant. Never grant FDA to its generic Python
runtime or edit the TCC database. Full Disk Access is a macOS filesystem
permission, separate from MCP bearer authentication; it is not an OAuth
login or a Mail account sign-in.

The selected runtime and dependencies are trusted application code. Nix
store paths are read-only; Brew runtime and package files may be writable
by the installing user. This design limits ambient access through a
general Python command. It does not protect against a compromised user
who can replace the trusted runtime or read the service's token.

## Verification

```sh
python -m pytest -q tests macos-helper/test_helper.py
```

Native tests build a disposable signed executable, reject arbitrary arguments,
exercise fixture SQL and schema over embedded HTTP, check the actual PID
path with `proc_pidpath`, validate bounded FTS and stdio, and poison both
Python and DYLD environment variables. They never open real mail. The
fixed-port HTTP test skips if 58435 is already occupied, avoiding changes
to a live service. Fixture tests establish process isolation and protocol
behavior; real FDA readiness requires a background probe after granting
the installed executable on each host.
