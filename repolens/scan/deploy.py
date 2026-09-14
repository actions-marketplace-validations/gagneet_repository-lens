"""Which Python server do the repository's deployment manifests actually run?

Two files that both construct `FastAPI()` are both import roots for `wiring`, so a copy
nothing deploys (`svc/server_copy.py` beside the `svc/server.py` a systemd unit runs)
ranks as high as the live one. This module reads the manifests that START a server and
names the repository files they run:

  systemd `*.service`         ExecStart, WorkingDirectory
  Dockerfile* / Containerfile CMD / ENTRYPOINT (exec and shell forms), WORKDIR, ENV, and
  (`Dockerfile.prod`,         COPY/ADD (which repository directory a WORKDIR holds), per
  `Dockerfile-api`, ...)      stage, with `FROM <stage>` inheriting. A Dockerfile is read
                              with both its own folder and the repository root as the
                              build context (`docker build -f dir/Dockerfile .` is as
                              common as building in `dir`)
  compose `*.yml|yaml`        block-style YAML only: command, entrypoint, working_dir,
                              image, build context/dockerfile/target (the Dockerfile it
                              names supplies the rest)
  Procfile, Procfile.*        each process line
  package.json                each script
  supervisord `*.conf|ini`    [program:x] command=, directory=, environment=
  `*.sh` / `*.bash`           real command lines only: `echo "python x.py"`, comments
                              and heredoc bodies run nothing

A program on a command line is understood when it is one of:

  - an ASGI/WSGI server naming the application on its command line:
    `uvicorn|gunicorn|hypercorn|granian|daphne|waitress-serve|cheroot ... module:attr`
    and `uwsgi --module|--wsgi-file` (also under `python -m`, with `--app-dir`/`--chdir`/
    `--pythonpath`, `module:create_app()`), `fastapi run|dev [path]`, `flask --app x run`;
  - `python file.py` or `python -m pkg.mod` (`pkg/__main__.py` for a package). The script
    is read too: an application it serves by name (`uvicorn.run("pkg.mod:app")`,
    `uvicorn.Config(...)`, `Granian(...)`, a gunicorn `BaseApplication`, or any
    "module:attr" string in it) is what it serves;
  - a shell (`sh -c '...'`, `bash -euo pipefail -c ...`, `sh ./entry.sh`) or a shell
    script in the repository (`.sh`, or a `#!` naming a shell), which is followed with
    its arguments as `$@`;
  - a wrapper (`exec`, `gosu app`, `poetry run`, `tini --`) around one of these;
  - a setup command that exits without starting another program (`mkdir`, `pip install`,
    `alembic upgrade head`), or a long-running program that cannot host this repository's
    Python application (`nginx`, `redis-server`, ...: `_NOT_APP_SERVERS`).

Nothing is executed and nothing is imported: manifests are read as text. A manifest that
is parsed is read within `max_file_bytes`, like every other source read; the lexical
checks for formats that are not parsed (below) read up to 64 MiB of a file in 1 MiB
chunks, on bytes, with bounded patterns. Paths are resolved without leaving the root: a
symlink is not followed, and a script reached through a linked directory is not opened.

It FAILS CLOSED. Demotion lowers a finding's priority, so whatever a deployment manifest
does that is not fully understood makes the deployment unknown: the target is `blocking`,
and the caller must then treat the deployment as unknown rather than guess. Blocking are:

  - a program not understood (`bin/start` outside the repository, `make run`, a console
    script, `$PYTHON -m uvicorn`), a shell reading its commands from elsewhere, a command
    line longer than 64 KiB;
  - an application that cannot be named statically (`uvicorn $APP_MODULE`), more than one
    application-shaped argument, or a name more than one scanned file could be. Every
    candidate counts: each possible working directory AND every module-map candidate
    (PYTHONPATH, an installed checkout, a `src/` layout);
  - a run script that starts a subprocess, names its application at run time, changes
    `sys.path` or the working directory (`sys.path.insert`, `os.chdir`), or passes
    `app_dir=` to the server;
  - a manifest that cannot be read (too large, binary, invalid UTF-8) or parsed, including
    compose YAML this line reader cannot follow (flow style, a service header with a
    value, inconsistent indentation, service keys outside a `services:` mapping), and any
    exception while reading one; compose anchors, merge keys, `extends:`/`include:`;
  - an image whose command is not in the repository: a compose service running an image
    with no command of its own, a service naming no image, build or command, and a final
    Dockerfile stage with no ENTRYPOINT or CMD. An image whose default command cannot serve
    this application does not block: a bare OS or interpreter image (`python`, `debian`,
    `alpine`, `scratch`, ...) or a backing service (`postgres`, `redis`, `nginx`, ...:
    `_INERT_IMAGES`);
  - a manifest symlink that leaves the root (or points at a file of another name), a
    linked directory that leaves the root, and a directory that cannot be listed;
  - every deployment format this module does not interpret (below).

Where a command runs is evidence only when it is known: a Procfile's or package.json's
own directory, a Dockerfile WORKDIR a COPY/ADD filled from a known repository directory,
`cd "$(dirname "$0")"`, a relative `cd` from a known directory, or an absolute path
(`/srv/example/backend/app`) whose last TWO or more segments name a scanned directory. A
one-segment match (`/app` -> `app/`) and an unmapped WORKDIR or WorkingDirectory are not
evidence: an unknown working directory stands for every scanned directory, and the name
must still resolve to exactly one file.

Two kinds of evidence are weaker than a deployment:

  auxiliary   package.json scripts, files under tests/, CI, scripts/ or dev tooling, files
              named for dev/test/CI (`docker-compose.dev.yml`), `--reload` servers. What
              they run is live, but they never make the deployment known: a CI job
              starting a fixture server says nothing about what production runs. A
              program one runs that is not understood does not block, but an application
              one names that does not resolve to exactly one file does (`uvicorn
              main:app` with two `main.py`, a module that is not here). Formats below found
              under CI or tooling directories still do, and so does a CI workflow or
              tooling script that deploys (`ssh host ...`, `kubectl apply`, `helm upgrade`,
              `gcloud run deploy`, `fly deploy`, `docker push`, a deploy action).
  unread      a deployment format this module does not interpret, detected by name or
              lexically (bounded, on bytes, so a file too large or not UTF-8 is still
              checked): Kubernetes/Helm (`containers:`, also in flow style, `Chart.yaml`,
              a `values*.yaml` setting command/args), ECS, App Engine (`app.yaml`, or any
              YAML with a top-level `entrypoint:`), `fly.toml`/`fly.<env>.toml`,
              `render.yaml`, Heroku `app.json`/`heroku.yml`,
              Railway, Nixpacks, Vercel, Azure Functions (`host.json`), SAM/CloudFormation
              (`AWS::Serverless`, `AWS::Lambda`), Serverless, Zappa, Cloud Foundry
              `manifest.yml`, Cloud Build `run deploy`, Terraform start commands, pm2
              `ecosystem.config.*`, circus, uWSGI and PasteDeploy ini files, Elastic
              Beanstalk / Platform.sh `.platform/`, systemd drop-ins (`*.service.d/`),
              templated manifests (`.j2`, `.tmpl`, `.in`, ...), and any line starting an
              ASGI/WSGI server on a named application (not `--reload`) in a Makefile,
              justfile, other YAML (Taskfile, Ansible), `web.config`, `startup.txt`,
              `.cmd`/`.bat`/`.ps1` or Bicep (`appCommandLine`). Any one is blocking,
              since it may start a server nothing here read.
"""
from __future__ import annotations

import ast
import json
import os
import posixpath
import re
import shlex
import stat
import warnings
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..core.files import SkipRule
from ..impact.source import read_source
from .settings import ScanSettings
from .wiring import ModuleMap

#: Servers that take the application as a positional `module:attr` (or a `--app` value).
SERVERS = frozenset({"uvicorn", "gunicorn", "hypercorn", "granian", "daphne", "waitress-serve",
                     "cheroot"})
#: `python -m <module>` spellings of those servers.
_MODULE_SERVERS = {"uvicorn": "uvicorn", "gunicorn": "gunicorn", "hypercorn": "hypercorn",
                   "granian": "granian", "daphne": "daphne", "waitress": "waitress-serve",
                   "cheroot": "cheroot"}
_CLIS = frozenset({"fastapi", "flask"})
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh"})
_PYTHON = re.compile(r"^(python|pypy)(\d+(\.\d+)*)?$")
_DYNAMIC = re.compile(r"[$`]|%[A-Za-z(]|\{\{|\{%")
_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_MODULE = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$")
_APP_SPEC = re.compile(r"^[A-Za-z_][\w.]*(:[A-Za-z_]\w*(\(.*\))?)?$")
#: A "module:attr" string in a run script: an application handed to something by name.
_SPEC_STRING = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(\(\))?$")
_COMPOSE = re.compile(r"^(docker-)?compose([.-][\w.-]+)?\.ya?ml$")
_REDIRECT = re.compile(r"^\d*[<>&]*[<>][<>&]*$")
_POSITIONAL = re.compile(r"^\$(?:([@*]|\d)|\{([@*]|\d)\})$")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
#: `cd "$(dirname "$0")"`, `cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."`.
_SCRIPT_DIR = re.compile(r"^(?:\$\(.*\bdirname\b.*(?:\$0|\$\{0\}|BASH_SOURCE).*\)|\$\{0%/\*\})"
                         r"(?P<rest>(?:/[^$`]*)?)$")
_FUNCTION = re.compile(r"^[ \t]*(?:function[ \t]+([A-Za-z_][\w.-]*)|([A-Za-z_][\w.-]*)[ \t]*\(\))",
                       re.MULTILINE)
#: Words that run the command after them: `exec`, `nohup`, `poetry run`, `sudo -u app`.
_WRAPPERS = frozenset({
    "exec", "nohup", "sudo", "env", "time", "nice", "ionice", "stdbuf", "timeout", "setsid",
    "chrt", "taskset", "poetry", "uv", "pipenv", "pdm", "rye", "hatch", "conda", "micromamba",
    "run", "run-program", "newrelic-admin", "ddtrace-run", "opentelemetry-instrument",
    "doppler", "dotenv", "dumb-init", "tini", "gosu", "su-exec", "chpst", "xvfb-run",
    "wait-for-it", "wait-for-it.sh", "dockerize", "with-contenv", "s6-setuidgid", "command",
    "runuser", "setpriv", "catchsegv", "flock"})
#: Wrappers that take positional arguments before the command (`gosu app uvicorn ...`).
_WRAPPER_POSITIONALS = {"gosu": 1, "su-exec": 1, "chpst": 1, "timeout": 1, "taskset": 1, "chrt": 1,
                        "wait-for-it": 1, "wait-for-it.sh": 1, "s6-setuidgid": 1, "flock": 1}
_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{",
                       "}", "esac", "in"})
_SEPARATORS = frozenset({"&&", "||", ";", "|", "&", ";;", "(", ")", "|&", ";&", ";;&"})
#: Commands that do their work and exit without starting another program: the setup steps
#: of an entrypoint script. One whose arguments name an interpreter, server or shell
#: (`xargs uvicorn`, `find . -exec python`) is not trusted.
_SETUP_COMMANDS = frozenset({
    ":", "true", "false", "echo", "printf", "cat", "test", "[", "[[", "sleep", "wait", "exit",
    "return", "set", "unset", "shift", "trap", "umask", "ulimit", "local", "declare", "readonly",
    "typeset", "let", "read", "shopt", "hash", "alias", "unalias", "type", "which", "export",
    "mkdir", "rmdir", "cp", "mv", "rm", "ln", "chmod", "chown", "chgrp", "touch", "ls", "pwd",
    "dirname", "basename", "realpath", "readlink", "date", "id", "whoami", "hostname", "uname",
    "printenv", "tee", "head", "tail", "grep", "egrep", "fgrep", "sed", "awk", "cut", "tr",
    "sort", "uniq", "wc", "tar", "gzip", "gunzip", "unzip", "zip", "curl", "wget", "sha256sum",
    "md5sum", "base64", "envsubst", "jq", "yq", "git", "pip", "pip3", "apt", "apt-get", "apk",
    "yum", "dnf", "microdnf", "alembic", "psql", "pg_isready", "pg_dump", "pg_restore",
    "createdb", "mysql", "redis-cli", "nc", "find", "rsync", "install", "useradd", "adduser",
    "groupadd", "addgroup", "update-ca-certificates", "openssl", "stat", "du", "df", "ps",
    "kill", "pkill", "mktemp", "seq", "expr", "logger", "cmp", "diff", "locale-gen", "dpkg",
    "ldconfig", "setcap", "ssh-keygen", "ssh-keyscan", "gpg", "shred", "sync", "truncate"})
#: `python -m <module>` that installs, migrates, tests or inspects, and serves no application.
_SETUP_MODULES = frozenset({"pip", "venv", "virtualenv", "ensurepip", "alembic", "pytest",
                            "unittest", "compileall", "py_compile", "json.tool", "site",
                            "http.server", "mypy", "ruff", "black", "isort", "flake8"})
#: Long-running programs that cannot host this repository's Python application. Anything
#: else a deployment manifest starts that is not understood blocks.
_NOT_APP_SERVERS = frozenset({
    "nginx",         # proxy/static server; it forwards to an application server started elsewhere
    "caddy",         # proxy/static server, same
    "envoy",         # proxy; no in-process application hosting
    "haproxy",       # load balancer; no in-process application hosting
    "redis-server",  # cache/queue store; runs no Python module
    "memcached",     # cache; runs no Python module
    "postgres",      # database server; runs SQL, not a Python module
})
#: JavaScript runtimes and package runners. They cannot import a Python module, but they can
#: spawn one (`child_process.spawn("uvicorn", ...)`, a package.json script), so they are
#: trusted only when no JavaScript file or package.json in the repository names a Python
#: interpreter or server.
_NODE = frozenset({"node", "nodejs", "npm", "yarn", "pnpm", "bun", "npx"})
#: Options that take a value, per server: the value is never the application.
_VALUE_FLAGS = {
    "uvicorn": {"--host", "--port", "--uds", "--fd", "--reload-dir", "--reload-include",
                "--reload-exclude", "--reload-delay", "--workers", "--loop", "--http", "--ws",
                "--ws-max-size", "--ws-max-queue", "--ws-ping-interval", "--ws-ping-timeout",
                "--lifespan", "--interface", "--env-file", "--log-config", "--log-level",
                "--root-path", "--limit-concurrency", "--limit-max-requests", "--backlog",
                "--timeout-keep-alive", "--timeout-graceful-shutdown", "--ssl-keyfile",
                "--ssl-certfile", "--ssl-keyfile-password", "--ssl-version", "--ssl-cert-reqs",
                "--ssl-ca-certs", "--ssl-ciphers", "--header", "--forwarded-allow-ips",
                "--app-dir", "--h11-max-incomplete-event-size", "--ws-per-message-deflate",
                "--timeout-worker-healthcheck"},
    "gunicorn": {"-c", "--config", "-b", "--bind", "--backlog", "-w", "--workers", "-k",
                 "--worker-class", "--threads", "--worker-connections", "--max-requests",
                 "--max-requests-jitter", "-t", "--timeout", "--graceful-timeout", "--keep-alive",
                 "--limit-request-line", "--limit-request-fields", "--limit-request-field_size",
                 "--chdir", "--pythonpath", "-e", "--env", "-p", "--pid", "--worker-tmp-dir",
                 "-u", "--user", "-g", "--group", "-m", "--umask", "--forwarded-allow-ips",
                 "--access-logfile", "--access-logformat", "--error-logfile", "--log-file",
                 "--log-level", "--log-config", "--log-config-json", "--log-syslog-to",
                 "--log-syslog-prefix", "--log-syslog-facility", "-n", "--name", "--keyfile",
                 "--certfile", "--ssl-version", "--cert-reqs", "--ca-certs", "--ciphers", "--paste",
                 "--statsd-host", "--statsd-prefix", "--dogstatsd-tags", "--proxy-allow-from",
                 "--reload-extra-file", "--reload-engine", "--logger-class", "--header-map",
                 "--forwarder-headers", "--raw-paste-global-conf", "--log-config-dict"},
    "hypercorn": {"-c", "--config", "-b", "--bind", "--insecure-bind", "--quic-bind", "-w",
                  "--workers", "-k", "--worker-class", "--root-path", "--certfile", "--keyfile",
                  "--keyfile-password", "--ca-certs", "--ciphers", "--log-level", "--log-config",
                  "--access-logfile", "--access-logformat", "--error-logfile", "--keep-alive",
                  "--graceful-timeout", "--read-timeout", "--backlog", "-u", "--user", "-g",
                  "--group", "-p", "--pid", "--server-name", "--max-requests",
                  "--max-requests-jitter", "-m", "--umask", "--statsd-host", "--statsd-prefix",
                  "--dogstatsd-tags", "--websocket-ping-interval", "--h11-max-incomplete-size",
                  "--h2-max-concurrent-streams", "--h2-max-header-list-size",
                  "--h2-max-inbound-frame-size", "--keep-alive-max-requests",
                  "--websocket-max-message-size", "--wsgi-max-body-size"},
    "granian": {"--host", "--port", "--interface", "--http", "--ws", "--workers", "--threads",
                "--blocking-threads", "--threading-mode", "--loop", "--task-impl", "--backlog",
                "--backpressure", "--http1-buffer-size", "--log-level", "--log-config",
                "--ssl-keyfile", "--ssl-keyfile-password", "--ssl-certificate", "--ssl-ca",
                "--ssl-protocol-min", "--url-path-prefix", "--respawn-interval",
                "--workers-lifetime", "--workers-kill-timeout", "--reload-paths",
                "--reload-ignore-dirs", "--reload-ignore-patterns", "--reload-ignore-paths",
                "--process-name", "--pid-file", "--working-dir", "--env-files",
                "--static-path-route", "--static-path-mount", "--static-path-expires",
                "--runtime-threads", "--runtime-blocking-threads", "--runtime-mode",
                "--workers-max-rss", "--rss-sample-interval", "--blocking-threads-idle-timeout",
                "--http1-header-read-timeout", "--http2-max-concurrent-streams"},
    "daphne": {"-p", "--port", "-b", "--bind", "-u", "--unix-socket", "--fd", "-e", "--endpoint",
               "-t", "--http-timeout", "--access-log", "--log-fmt", "--ping-interval",
               "--ping-timeout", "--application-close-timeout", "--root-path",
               "--websocket_timeout", "--websocket_connect_timeout", "--proxy-headers-host",
               "--proxy-headers-port", "-v", "--verbosity", "--server-name"},
    "waitress-serve": {"--host", "--port", "--listen", "--unix-socket", "--unix-socket-perms",
                       "--threads", "--url-scheme", "--url-prefix", "--ident", "--backlog",
                       "--recv-bytes", "--send-bytes", "--outbuf-overflow",
                       "--outbuf-high-watermark", "--inbuf-overflow", "--connection-limit",
                       "--cleanup-interval", "--channel-timeout", "--max-request-header-size",
                       "--max-request-body-size", "--asyncore-loop-timeout",
                       "--trusted-proxy", "--trusted-proxy-count", "--trusted-proxy-headers",
                       "--app"},
    "cheroot": {"--bind", "--chdir", "--server-name", "--threads", "--max", "--timeout",
                "--shutdown_timeout", "--request-queue-size", "--accepted-queue-size",
                "--accepted-queue-timeout"},
}
#: Options that change the working directory, and options that add to sys.path.
_CWD_FLAGS = {"gunicorn": ("--chdir",), "granian": ("--working-dir",), "cheroot": ("--chdir",)}
_PATH_FLAGS = {"uvicorn": ("--app-dir",), "gunicorn": ("--pythonpath",)}
#: Options whose value is the application.
_SPEC_FLAGS = {"waitress-serve": ("--app",)}
#: uWSGI options that load code or configuration beyond the one application named, or start
#: other programs: with any of them the application is not known from the command line.
_UWSGI_OPAQUE = re.compile(
    r"^--(?:ini|yaml|yml|xml|json|emperor|mount|eval|pyrun|pyshell|py-?import|python-import"
    r"|shared-(?:py)?import|import|spooler(?:-import)?|mule|(?:smart-)?attach-(?:control-)?daemon2?"
    r"|legion.*|exec-.*|hook-.*|call-.*|cron|unique-cron|worker-exec|app|wsgi-env-behaviou?r"
    r"|plugin-dir|asgi|pecan|paste|http-socket-modifier.*|route.*|static-map.*|ini-paste.*)$")
_UWSGI_MODULE = frozenset({"--module", "-w", "--wsgi", "--callable-module"})
_UWSGI_FILE = frozenset({"--wsgi-file", "--file"})
_FASTAPI_DEFAULTS = ("main.py", "app.py", "api.py", "app/main.py", "app/app.py", "app/api.py")
_FLASK_DEFAULTS = ("wsgi.py", "app.py")
#: More manifests than this and the deployment is reported unknown instead of half-read.
MAX_MANIFESTS = 5000
#: Scripts followed from a manifest, nested no deeper than this.
_MAX_DEPTH = 8
#: Characters one logical command line (continuations joined) may have before it blocks.
_MAX_COMMAND = 64 * 1024
#: Bytes a lexical check reads from one file before calling it unreadable.
_LEXICAL_CAP = 64 * 1024 * 1024
#: JavaScript files read looking for a spawned Python server before assuming there is one.
_MAX_JS_FILES = 20000
#: Directories whose manifests start servers for tests, CI, examples or development.
_AUXILIARY_DIRS = frozenset({
    "test", "tests", "testing", "e2e", "integration_tests", "fixtures", "mocks", ".github",
    ".gitlab", ".circleci", ".buildkite", ".devcontainer", ".vscode", ".husky", "ci", "scripts",
    "script", "tools", "tooling", "dev", "hack", "examples", "example", "samples", "sample",
    "demo", "demos", "docs", "doc", "benchmarks"})
#: Of those, the ones that hold test data, examples or editor setup rather than tooling: a
#: Kubernetes fixture under tests/ deploys nothing. CI and tooling directories (scripts/,
#: .github/, ci/, tools/, hack/) often hold the real deployment, so formats there still block.
_INERT_DIRS = frozenset({
    "test", "tests", "testing", "e2e", "integration_tests", "fixtures", "mocks", "examples",
    "example", "samples", "sample", "demo", "demos", "docs", "doc", "benchmarks", ".devcontainer",
    ".vscode", ".husky", "dev"})
#: A manifest named for a use other than production: `docker-compose.dev.yml`, `run_tests.sh`.
_AUXILIARY_NAME = re.compile(r"(?:^|[._-])(?:dev|develop|development|local|test|tests|testing|e2e|ci"
                             r"|debug|example|sample|demo|mock|fake)(?:[._-]|$)", re.IGNORECASE)
#: A development server: what it runs is live, but it is not the deployment.
_DEV_COMMAND = re.compile(r"(?:^|\s)--reload(?:[\s=]|$)|(?:^|\s)fastapi\s+dev(?:\s|$)")
#: Deployment formats not interpreted here, blocking by their presence alone.
_UNREAD_NAMES = frozenset({
    "app.yaml", "app.yml", "fly.toml", "render.yaml", "render.yml", "chart.yaml", "chart.yml",
    "kustomization.yaml", "kustomization.yml", "skaffold.yaml", "skaffold.yml", "apprunner.yaml",
    "apprunner.yml", ".platform.app.yaml", "railway.json", "railway.toml", "nixpacks.toml",
    "nixpacks.json", "zappa_settings.json", "zappa_settings.yaml", "zappa_settings.yml",
    "dockerrun.aws.json", "serverless.yml", "serverless.yaml", "serverless.json", "uwsgi.ini",
    "uwsgi.yaml", "uwsgi.yml", "uwsgi.xml", "vercel.json", "now.json", "host.json",
    "function.json", "circus.ini", "app.json", "heroku.yml", "samconfig.toml", "cdk.json",
    "pulumi.yaml", "pulumi.yml", "appspec.yml", "appspec.yaml", ".replit", "project.toml",
    "passenger_wsgi.py", "passengerfile.json", "procfile.tmpl"})
#: Directories that configure a platform which starts the application its own way.
_UNREAD_DIRS = frozenset({".platform", ".ebextensions", ".chalice"})
#: A manifest rendered by a template engine before it is used (`api.service.j2`).
_TEMPLATE_SUFFIXES = (".j2", ".jinja", ".jinja2", ".tmpl", ".tpl", ".template", ".erb", ".mustache",
                      ".hbs", ".gotmpl", ".in")
_CI_FILE = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$|(?:^|/)\.gitlab-ci\.ya?ml$"
                      r"|(?:^|/)\.gitlab/.+\.ya?ml$|(?:^|/)\.circleci/.+\.ya?ml$"
                      r"|(?:^|/)\.buildkite/.+\.ya?ml$|(?:^|/)bitbucket-pipelines\.ya?ml$"
                      r"|(?:^|/)azure-pipelines[^/]*\.ya?ml$|(?:^|/)\.drone\.ya?ml$"
                      r"|(?:^|/)\.travis\.ya?ml$|(?:^|/)\.woodpecker(?:/[^/]+|\.ya?ml)$"
                      r"|(?:^|/)Jenkinsfile$", re.IGNORECASE)


def _bytes_pattern(pattern: str, flags: int = 0) -> re.Pattern[bytes]:
    return re.compile(pattern.encode(), flags)


#: Lexical signs that a YAML file starts containers or processes: Kubernetes and Helm
#: (`containers:`), ECS (`containerDefinitions`), Render/DigitalOcean start commands,
#: Cloud Foundry (`applications:`), SAM/CloudFormation, Cloud Build deploy steps,
#: Ansible-written systemd units.
_UNREAD_YAML = _bytes_pattern(
    r"(?:^|[{,])[ \t-]*[\"']?(?:containers|initContainers|containerDefinitions|ContainerDefinitions"
    r"|startCommand|run_command)[\"']?[ \t]*:|^applications[ \t]*:|^entrypoint[ \t]*:|ExecStart[ \t]*="
    r"|AWS::(?:Serverless|Lambda|ECS|AppRunner|ElasticBeanstalk|Batch)"
    r"|\brun[\"']?[ \t]*,?[ \t]*[\"']?deploy\b|\b(?:app|functions)[\"']?[ \t]*,[ \t]*[\"']?deploy\b",
    re.MULTILINE)
_YAML_SERVICES = _bytes_pattern(r"^services[ \t]*:[ \t]*\r?$", re.MULTILINE)
_YAML_PROCESS = _bytes_pattern(r"^[ \t]+(?:command|entrypoint|image)[ \t]*:", re.MULTILINE)
_UNREAD_HCL = _bytes_pattern(
    r"\bcontainer_definitions\b|^[ \t]*containers?[ \t]*\{|^[ \t]*task[ \t]+\"[^\"]*\"[ \t]*\{"
    r"|ExecStart[ \t]*=|^[ \t]*(?:handler|app_command_line|start_command|startup_command|command"
    r"|entrypoint|entry_point|linux_fx_version|image_uri)[ \t]*=", re.MULTILINE)
_UNREAD_JSON = _bytes_pattern(r"\"(?:containers|initContainers|containerDefinitions|appCommandLine)\"\s*:"
                              r"|AWS::(?:Serverless|Lambda|ECS|AppRunner|ElasticBeanstalk|Batch)")
#: A rendered template: any process-starting word at all.
_UNREAD_TEMPLATE = _bytes_pattern(
    r"\b(?:uvicorn|gunicorn|hypercorn|granian|daphne|waitress-serve|uwsgi|cheroot|fastapi|flask)\b"
    r"|^[ \t-]*[\"']?(?:command|entrypoint|args|cmd|containers|startCommand|ExecStart)[\"']?[ \t]*[:=]"
    r"|\[program:|\[watcher:|\bpython[\d.]*[ \t]+\S|^[ \t]*(?:CMD|ENTRYPOINT)\b", re.MULTILINE)
#: An ini/conf file that starts a Python process through a tool not read here.
_UNREAD_INI = _bytes_pattern(r"^[ \t]*\[(?:uwsgi|circus|watcher:[^\]]*|server:[^\]]*|app:[^\]]*"
                             r"|composite:[^\]]*|pipeline:[^\]]*)\]", re.MULTILINE)
#: A Helm values file (with or without its chart here) that sets a container's command.
_VALUES_COMMAND = _bytes_pattern(r"^[ \t-]*[\"']?(?:command|args|entrypoint)[\"']?[ \t]*:", re.MULTILINE)
#: A line that starts an ASGI/WSGI server on a named application, in a file whose format
#: is not read here (Makefile, Taskfile, Ansible task, web.config, startup.txt, .ps1, ...).
#: A development server (`--reload`) is not a deployment. Bounded repetitions: no line
#: can make this quadratic.
_SERVER_LINE = _bytes_pattern(
    r"^(?![^\n]{0,4096}--reload)[^\n]{0,1024}?\b(?:uvicorn|gunicorn|hypercorn|granian|daphne|waitress-serve"
    r"|uwsgi)\b[^\n]{0,1024}?[\s'\"=][A-Za-z_][\w.]{0,200}:[A-Za-z_]", re.MULTILINE)
#: Bicep / ARM start commands.
_START_COMMAND = _bytes_pattern(r"\b(?:appCommandLine|startupCommand|startup_command)\b")
_SUPERVISOR_PROGRAM = _bytes_pattern(r"^[ \t]*\[(?:fcgi-)?program:", re.MULTILINE)
#: A CI workflow or tooling script that deploys: what it starts runs somewhere this
#: repository's manifests may not show.
_CI_DEPLOY = _bytes_pattern(
    r"\bssh[ \t]+(?:-\S+[ \t]+)*[^\s-]\S*[ \t]+\S|\bscp\b|\brsync\b[^\n]{0,4096}?\s[^\s:]{0,1024}:"
    r"|\bgcloud[ \t]+(?:beta[ \t]+|alpha[ \t]+)?(?:run|app|functions)[ \t]+deploy\b"
    r"|\bgcloud[ \t]+compute[ \t]+(?:ssh|instances[ \t]+create)"
    r"|\bkubectl[ \t]+(?:apply|create|replace|set[ \t]+image|rollout|run|patch)\b"
    r"|\bhelm(?:file)?[ \t]+(?:upgrade|install|sync|apply)\b|\bflyctl?[ \t]+deploy\b"
    r"|\b(?:docker|podman)[ \t]+(?:push|stack[ \t]+deploy|service[ \t]+(?:create|update))\b"
    r"|\b(?:serverless|sls|sam|cdk|pulumi|copilot|eb|railway|vercel|netlify|zappa|chalice)[ \t]+"
    r"(?:deploy|up|update)\b|\bheroku[ \t]+(?:container:release|releases|deploy)"
    r"|\bterraform[ \t]+apply\b|\bansible-playbook\b|\baws[ \t]+(?:ecs|lambda|apprunner|elasticbeanstalk"
    r"|deploy)[ \t]|\baz[ \t]+(?:webapp|functionapp|containerapp|container)[ \t]"
    r"|\bgit[ \t]+push[ \t]+\S*(?:heroku|dokku)|\buses:[ \t]*[\w.-]+/[\w.-]*(?:deploy|ssh)[\w.-]*",
    re.IGNORECASE)
_PYTHON_SPAWN_JS = re.compile(r"\b(?:python[\d.]*|uvicorn|gunicorn|hypercorn|granian|daphne|waitress-serve"
                              r"|uwsgi|fastapi|flask)\b|\.py[\"'`]")
_JS_SPAWN = re.compile(r"child_process|\bexeca\b|\bspawn\s*\(|\bexecFile\s*\(|\bexecSync\s*\(|\bfork\s*\(")
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
#: Calls that return a string from the environment or build one: the application is unnamed.
_STRING_CALLS = frozenset({"getenv", "get", "format", "join", "environ", "format_map", "replace",
                           "strip", "lower", "upper", "pop", "setdefault"})


@dataclass(frozen=True)
class Target:
    """One Python process a manifest starts."""

    manifest: str
    line: int
    command: str
    #: An ASGI/WSGI server or framework CLI, rather than a bare `python file.py`.
    server: bool
    files: tuple[str, ...] = ()
    #: Why nothing resolved ("" when `files` is non-empty).
    unresolved: str = ""
    #: Unresolved in a way that could name ANY file: the deployment is unknown.
    blocking: bool = False
    #: From tests, CI, dev tooling or a package.json script: what it runs is live, but it
    #: is not evidence of what the deployment runs.
    auxiliary: bool = False


@dataclass(frozen=True)
class Deployment:
    """The manifests read and every Python process they start."""

    manifests: tuple[str, ...]
    targets: tuple[Target, ...]

    @property
    def blocking(self) -> tuple[Target, ...]:
        """Targets that could name any file: when present, the deployment is unknown."""
        return tuple(t for t in self.targets if t.blocking)


@dataclass(frozen=True)
class _Resolution:
    files: tuple[str, ...] = ()
    reason: str = ""
    blocking: bool = False


def _join(base: str, rel: str) -> str | None:
    joined = posixpath.normpath(posixpath.join(base, rel)) if base else posixpath.normpath(rel or ".")
    if joined == ".":
        return ""
    return None if joined == ".." or joined.startswith(("../", "/")) else joined


def _literal_parts(path: str) -> list[str]:
    """The trailing path components with nothing substituted at run time, minus `.`/`..`:
    `"$DIR/../svc/api.py"` -> ["svc", "api.py"]."""
    parts: list[str] = []
    for part in reversed(path.replace("\\", "/").split("/")):
        if _DYNAMIC.search(part) or part in ("~",):
            break
        parts.append(part)
    return [p for p in reversed(parts) if p not in ("", ".", "..")]


def _location(rel: str) -> str:
    """Where a module lives: `a/b.py`, `a/b/__init__.py` and `a/b/__main__.py` are all `a/b`."""
    stem = rel[:-3] if rel.endswith(".py") else rel
    for tail in ("/__init__", "/__main__"):
        if stem.endswith(tail):
            return stem[: -len(tail)]
    return "" if stem in ("__init__", "__main__") else stem


def _ambiguous(name: str, locations: list[str]) -> _Resolution:
    shown = ", ".join(locations[:4]) + (f" (+{len(locations) - 4} more)" if len(locations) > 4 else "")
    return _Resolution(reason=f"{name} could be more than one file ({shown})", blocking=True)


@dataclass(frozen=True)
class _Image:
    """What a Dockerfile stage copied from the repository, by image path. A source of None
    means content not from the repository (another image, a URL, a heredoc, a file the
    build generates): what is under that path is unknown."""

    copies: tuple[tuple[str, tuple[str, ...] | None], ...] = ()

    def resolve(self, path: str, resolver: _Resolver, *, directory: bool = False) -> tuple[str, ...] | None:
        """The repository paths image `path` can be, or None when that is not known."""
        path = posixpath.normpath("/" + path.lstrip("/"))
        found: list[str] = []
        for dest, sources in self.copies:
            if path == dest:
                rest = ""
            elif dest == "/":
                rest = path[1:]
            elif path.startswith(dest + "/"):
                rest = path[len(dest) + 1:]
            else:
                continue
            if sources is None:
                return None
            for source in sources:
                joined = _join(source, rest)
                if joined is not None and (resolver.is_dir(joined) if directory else resolver.exists(joined)):
                    found.append(joined)
        return tuple(dict.fromkeys(found)) or None


@dataclass(frozen=True)
class _Where:
    """Where a command runs. `bases`: the repository directories the working directory can
    be, or None when that is not known (any scanned directory). `image`: the container
    filesystem, when a Dockerfile says what it holds."""

    bases: tuple[str, ...] | None = None
    image: _Image | None = None

    def enter(self, path: str, resolver: _Resolver, script_dir: str | None = None) -> _Where:
        path = path.strip()
        if not path or path == "-" or path.startswith("~"):
            return replace(self, bases=None)
        if _DYNAMIC.search(path):
            match = _SCRIPT_DIR.match(path)
            if match and script_dir is not None:
                here = _Where((script_dir,), self.image)
                rest = match.group("rest").strip("/")
                return here.enter(rest, resolver) if rest else here
            parts = _literal_parts(path)
            found = resolver.dirs_ending(parts) if len(parts) >= 2 and ".." not in path else ()
            return replace(self, bases=found or None)
        if path.startswith("/"):
            if self.image is not None:
                return replace(self, bases=self.image.resolve(path, resolver, directory=True))
            mapped = resolver.map_dir(path)
            return replace(self, bases=(mapped,) if mapped is not None else None)
        if self.bases is None:
            return self  # relative to a directory nobody knows: still unknown
        joined = tuple(dict.fromkeys(b for b in (_join(base, path) for base in self.bases)
                                     if b is not None and resolver.is_dir(b)))
        return replace(self, bases=joined or None)

    def union(self, other: _Where) -> _Where:
        if self.bases is None or other.bases is None:
            return replace(self, bases=None)
        return replace(self, bases=tuple(dict.fromkeys((*self.bases, *other.bases))))


class _Resolver:
    """Maps a manifest's paths and module names onto the scanned Python files."""

    def __init__(self, s: ScanSettings, python_rels: list[str] | tuple[str, ...], modules: ModuleMap):
        self.root = s.root
        self.rels = frozenset(python_rels)
        self.modules = modules
        self.settings = s
        self.skip = SkipRule(s.skip_parts)
        self.dirs: set[str] = {""}
        self.by_name: dict[str, list[str]] = {}
        for rel in sorted(self.rels):
            parts = rel.split("/")
            self.by_name.setdefault(parts[-1], []).append(rel)
            for i in range(1, len(parts)):
                self.dirs.add("/".join(parts[:i]))
        #: Scripts a manifest followed: not read again on their own.
        self.followed: set[str] = set()
        #: Dockerfiles a (non-auxiliary) compose service builds, read there with its context.
        self.built: set[str] = set()
        #: Basenames of systemd units and whether any supervisord program was found.
        self.units: set[str] = set()
        self.supervised = False
        self._spawns: bool | None = None

    # ── the filesystem ────────────────────────────────────────────────────────────
    def _path(self, rel: str) -> Path | None:
        if rel is None or (rel and self.skip.matches(tuple(rel.split("/")))):
            return None
        return self.root / rel if rel else self.root

    # A path the manifest spells that the OS refuses (too long, a loop) is not a file here.
    def exists(self, rel: str) -> bool:
        path = self._path(rel)
        try:
            return path is not None and not path.is_symlink() and path.exists()
        except OSError:
            return False

    def is_dir(self, rel: str) -> bool:
        path = self._path(rel)
        try:
            return path is not None and not path.is_symlink() and path.is_dir()
        except OSError:
            return False

    def is_file(self, rel: str) -> bool:
        path = self._path(rel)
        try:
            return path is not None and rel != "" and not path.is_symlink() and path.is_file()
        except OSError:
            return False

    def inside(self, rel: str) -> bool:
        """Whether `rel`, every symlink on the way resolved, is still inside the root."""
        try:
            real = Path(os.path.realpath(self.root / rel))
            return real.is_relative_to(Path(os.path.realpath(self.root)))
        except (OSError, ValueError):
            return False

    def shebang(self, rel: str) -> str:
        """The interpreter a file's `#!` line names (`sh`, `python3`), or "". A file reached
        through a symlinked directory that leaves the root is not opened."""
        if not self.inside(rel):
            return ""
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(self.root / rel, flags), "rb") as stream:
                first = stream.readline(256)
        except OSError:
            return ""
        if not first.startswith(b"#!"):
            return ""
        words = first[2:].decode("latin-1").split()
        if not words:
            return ""
        name = posixpath.basename(words[0])
        if name == "env":
            rest = [w for w in words[1:] if not w.startswith("-")]
            return posixpath.basename(rest[0]) if rest else ""
        return name

    def python_spawns(self) -> bool:
        """Whether any JavaScript file or package.json here could start a Python server."""
        if self._spawns is None:
            self._spawns = self._scan_spawns()
        return self._spawns

    def _scan_spawns(self) -> bool:
        seen = 0
        for parent, directories, files in os.walk(self.root, followlinks=False):
            here = Path(parent)
            directories[:] = [d for d in directories if not (here / d).is_symlink()
                              and not self.skip.matches((here / d).relative_to(self.root).parts)]
            for name in files:
                if not (name.endswith(_JS_SUFFIXES) or name == "package.json"):
                    continue
                seen += 1
                if seen > _MAX_JS_FILES:
                    return True
                read = read_source(self.root, here / name, self.settings.max_file_bytes)
                if read.text is None:
                    if read.status in ("too_large", "invalid_utf8", "binary", "unreadable"):
                        return True
                    continue
                if _PYTHON_SPAWN_JS.search(read.text) and (name == "package.json" or _JS_SPAWN.search(read.text)):
                    return True
        return False

    # ── directories ───────────────────────────────────────────────────────────────
    def map_dir(self, path: str) -> str | None:
        """`/srv/example/backend/app` -> `backend/app`: the longest suffix, of at least TWO
        segments, of a path from another machine that names a scanned directory. `/app`
        naming a repository `app/` is coincidence, not evidence."""
        parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".", "..", "~")]
        for k in range(len(parts), 1, -1):
            if "/".join(parts[-k:]) in self.dirs:
                return "/".join(parts[-k:])
        return None

    def dirs_ending(self, parts: list[str]) -> tuple[str, ...]:
        tail = "/".join(parts)
        return tuple(sorted(d for d in self.dirs if d and (d == tail or d.endswith("/" + tail))))

    def _ending(self, tail: str) -> list[str]:
        """Scanned files at `tail` below ANY directory."""
        return [r for r in self.by_name.get(posixpath.basename(tail), ()) if r == tail or r.endswith("/" + tail)]

    # ── Python files and modules ──────────────────────────────────────────────────
    def file(self, token: str, where: _Where) -> _Resolution:
        """The one scanned file `python <token>` runs."""
        if _DYNAMIC.search(token):
            parts = _literal_parts(token)
            if not parts or _DYNAMIC.search(token.replace("\\", "/").rsplit("/", 1)[-1]):
                return _Resolution(reason=f"the path {token!r} is chosen at run time", blocking=True)
            return self._unique(token, self._ending("/".join(parts)))
        if token.startswith(("/", "~")):
            if where.image is not None and token.startswith("/"):
                found = where.image.resolve(token, self)
                if found is not None:
                    return self._unique(token, [f for f in found if f in self.rels], on_disk=found)
            mapped = self.map_dir(posixpath.dirname(token))
            if mapped is not None:
                candidate = _join(mapped, posixpath.basename(token))
                if candidate in self.rels:
                    return _Resolution((candidate,))
            return self._unique(token, self.by_name.get(posixpath.basename(token), []))
        if where.bases is None:
            clean = posixpath.normpath(token)
            if clean.startswith("../"):
                return self._unique(token, self.by_name.get(posixpath.basename(token), []))
            return self._unique(token, self._ending(clean))
        candidates = [c for c in (_join(b, token) for b in where.bases) if c is not None]
        return self._unique(token, [c for c in candidates if c in self.rels],
                            on_disk=[c for c in candidates if self.is_file(c)])

    def _unique(self, token: str, hits: list[str], on_disk: list[str] | tuple[str, ...] = ()) -> _Resolution:
        hits = sorted(set(hits))
        if len(hits) == 1:
            return _Resolution((hits[0],))
        if hits:
            return _ambiguous(token, hits)
        for candidate in on_disk:
            if self.skip.matches(tuple(candidate.split("/"))):
                return _Resolution(reason=f"{candidate} is excluded from the scan", blocking=True)
            return _Resolution(reason=f"{candidate} is not among the scanned Python files", blocking=True)
        return _Resolution(reason=f"no {token} in the repository", blocking=True)

    def module(self, name: str, where: _Where, *, run_main: bool = False) -> _Resolution:
        """The files importing `name` runs. `run_main`: `python -m name`, which for a
        package runs its `__main__.py` (after its `__init__.py`). Every candidate counts:
        each possible working directory, and whatever the module map says the name can be
        (PYTHONPATH, an installed checkout, a `src/` layout). More than one place is
        ambiguous and blocking."""
        if _DYNAMIC.search(name):
            return _Resolution(reason=f"the module {name!r} is chosen at run time", blocking=True)
        if not _MODULE.match(name):
            return _Resolution(reason=f"{name!r} is not a module name", blocking=True)
        path = name.replace(".", "/")
        suffixes = (".py", "/__init__.py", *(("/__main__.py",) if run_main else ()))
        hits: set[str] = set()
        for suffix in suffixes:
            if where.bases is None:
                hits.update(self._ending(path + suffix))
            else:
                hits.update(c for c in (_join(b, path + suffix) for b in where.bases) if c in self.rels)
        hits.update(self.modules.candidates(name))
        if run_main:
            hits.update(self.modules.candidates(name + ".__main__"))
        if not hits:
            return _Resolution(reason=f"no module {name} in the repository", blocking=True)
        locations = sorted({_location(h) for h in hits})
        if len(locations) > 1:
            return _ambiguous(name, locations)
        ordered = sorted(hits, key=lambda h: (h.endswith("/__main__.py"), h.endswith("__init__.py"), h))
        # Importing `a.b` runs `a/__init__.py` first.
        folder = posixpath.dirname(locations[0])
        for _ in range(name.count(".")):
            init = f"{folder}/__init__.py" if folder else "__init__.py"
            if init in self.rels:
                ordered.append(init)
            folder = posixpath.dirname(folder)
        return _Resolution(tuple(dict.fromkeys(ordered)))

    # ── scripts ───────────────────────────────────────────────────────────────────
    def program(self, program: str, where: _Where, manifest: str) -> list[str]:
        """The repository files a program path (`bin/start`, `/entrypoint.sh`) can be."""
        if _DYNAMIC.search(program):
            parts = _literal_parts(program)
            if len(parts) < 2 or _DYNAMIC.search(program.rsplit("/", 1)[-1]):
                return []
            return self._files_ending(parts)
        if program.startswith("/"):
            if where.image is not None:
                return [f for f in where.image.resolve(program, self) or () if self.is_file(f)]
            mapped = self.map_dir(posixpath.dirname(program))
            candidate = _join(mapped, posixpath.basename(program)) if mapped is not None else None
            return [candidate] if candidate and self.is_file(candidate) else []
        if program.startswith("~"):
            return []
        if "/" not in program:
            # Looked up on PATH: only a copy into the image's PATH is known.
            if where.image is None:
                return []
            found: list[str] = []
            for directory in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
                found.extend(f for f in where.image.resolve(f"{directory}/{program}", self) or () if self.is_file(f))
            return list(dict.fromkeys(found))
        bases = where.bases if where.bases is not None else (posixpath.dirname(manifest), "")
        return list(dict.fromkeys(c for c in (_join(b, program) for b in bases) if c and self.is_file(c)))

    def _files_ending(self, parts: list[str]) -> list[str]:
        for k in range(len(parts), 1, -1):
            candidate = "/".join(parts[-k:])
            if self.is_file(candidate):
                return [candidate]
        return []

    # ── what a Python run script serves ───────────────────────────────────────────
    def served(self, rel: str) -> tuple[list[str], str]:
        """The "module:attr" applications the script `rel` serves in-process, and why the
        script makes the deployment unknown ("" when it does not)."""
        tree = self.settings.parse_cache.parse(self.root / rel, self.settings.max_file_bytes)
        if tree is None:
            return [], f"{rel} could not be parsed"
        return _served(tree, rel)


# ── reading a Python run script ───────────────────────────────────────────────────
#: Calls that serve the application given as an argument: qualified name -> (keyword, position).
_SERVE_CALLS = {
    "uvicorn.run": ("app", 0), "uvicorn.main.run": ("app", 0), "uvicorn.Config": ("app", 0),
    "uvicorn.config.Config": ("app", 0), "granian.Granian": ("target", 0),
    "granian.server.Granian": ("target", 0), "hypercorn.asyncio.serve": ("app", 0),
    "hypercorn.trio.serve": ("app", 0), "waitress.serve": ("app", 0),
    "werkzeug.serving.run_simple": ("application", 2), "werkzeug.run_simple": ("application", 2),
    "bjoern.run": ("wsgi_app", 0), "cheroot.wsgi.Server": ("wsgi_app", 1),
    "cheroot.wsgi.WSGIServer": ("wsgi_app", 1), "daphne.server.Server": ("application", 0),
    "meinheld.server.run": ("app", 0), "aiohttp.web.run_app": ("app", 0),
}
#: Calls that start a server from the command line or the environment, or another program.
_OPAQUE_CALLS = re.compile(
    r"^(?:subprocess\..+|os\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*)|pty\.spawn"
    r"|asyncio\.create_subprocess_\w+|uvicorn\.main\.main|uvicorn\.main|gunicorn\.app\.wsgiapp\.run"
    r"|hypercorn\.__main__\.main|granian\.cli\.\w+|runpy\.run_\w+|multiprocessing\..*Process"
    r"|importlib\.import_module|__import__|exec|eval|sh\..+|plumbum\..+|pexpect\.spawn)$")
#: Calls that change where a run script's imports and "module:attr" names are looked up.
_PATH_CALLS = re.compile(r"^(?:sys\.path\.(?:insert|append|extend|remove|pop|clear)|os\.chdir|site\.addsitedir"
                         r"|contextlib\.chdir)$")
_GUNICORN_BASES = frozenset({"gunicorn.app.base.BaseApplication", "gunicorn.app.base.Application",
                             "gunicorn.app.wsgiapp.WSGIApplication"})


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def _served(tree: ast.Module, rel: str) -> tuple[list[str], str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    constants = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
                 and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
                 for t in n.targets if isinstance(t, ast.Name)}
    specs: list[str] = []
    opaque = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and _SPEC_STRING.match(node.value):
            specs.append(node.value)
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_qualified(t.value if isinstance(t, ast.Subscript) else t, aliases) == "sys.path"
                   for t in targets):
                opaque = opaque or f"{rel} changes sys.path, so what it imports is not known"
        elif isinstance(node, ast.ClassDef):
            if any(_qualified(b, aliases) in _GUNICORN_BASES for b in node.bases):
                load = next((f for f in node.body if isinstance(f, ast.FunctionDef) and f.name == "load"), None)
                returns = [r.value for r in ast.walk(load) if isinstance(r, ast.Return)] if load else []
                if not returns or not all(isinstance(v, (ast.Name, ast.Attribute)) or (
                        isinstance(v, ast.Call) and isinstance(v.args[0] if v.args else None, ast.Constant))
                        for v in returns):
                    opaque = opaque or f"{rel} runs a gunicorn application whose app is not named statically"
        if not isinstance(node, ast.Call):
            continue
        name = _qualified(node.func, aliases)
        if name and _PATH_CALLS.match(name):
            opaque = opaque or f"{rel} calls {name}(), so what it imports is not known"
            continue
        if name and _OPAQUE_CALLS.match(name):
            if name in ("importlib.import_module", "__import__") and node.args and isinstance(
                    node.args[0], ast.Constant):
                continue
            opaque = opaque or f"{rel} calls {name}(), which may start a server nothing here reads"
            continue
        if name not in _SERVE_CALLS:
            continue
        keyword, position = _SERVE_CALLS[name]
        if any(k.arg is None for k in node.keywords) or any(isinstance(a, ast.Starred) for a in node.args):
            opaque = opaque or f"{rel} passes {name}() its application in unpacked arguments"
            continue
        if any(k.arg == "app_dir" for k in node.keywords):
            opaque = opaque or f"{rel} passes {name}() an app_dir, so the application's file is not known"
            continue
        arg = node.args[position] if len(node.args) > position else next(
            (k.value for k in node.keywords if k.arg == keyword), None)
        if isinstance(arg, ast.Name) and arg.id in constants:
            value: str | None = constants[arg.id]
        elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            value = arg.value
        elif arg is None or isinstance(arg, (ast.Name, ast.Attribute)) or (
                isinstance(arg, ast.Call) and _qualified(arg.func, aliases).rsplit(".", 1)[-1] not in _STRING_CALLS):
            continue  # an application object: its import is followed
        else:
            value = None
        if value is not None and _SPEC_STRING.match(value):
            specs.append(value)
        else:
            opaque = opaque or f"{rel} serves an application chosen at run time"
    return list(dict.fromkeys(specs)), opaque


# ── reading command lines ─────────────────────────────────────────────────────────
def _expand_positionals(argv: list[str], args: list[str] | None) -> list[str]:
    """`"$@"` in a followed script -> the arguments it was given."""
    if args is None:
        return argv
    out: list[str] = []
    for word in argv:
        match = _POSITIONAL.match(word)
        if not match:
            out.append(word)
            continue
        key = match.group(1) or match.group(2)
        if key in ("@", "*"):
            out.extend(args)
        elif key != "0" and int(key) <= len(args):
            out.append(args[int(key) - 1])
        else:
            out.append(word)
    return out


def _expand(word: str, local: dict[str, str]) -> str:
    """Variables the script itself assigned: `PY=python3; $PY -m ...`. Values from the
    environment a manifest declares can be overridden at run time and are not used."""
    def value(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return local.get(name, match.group(0))
    return _VARIABLE.sub(value, word) if "$" in word else word


def _names_program(word: str) -> bool:
    name = posixpath.basename(word)
    return bool(_PYTHON.match(name)) or name in SERVERS or name in _CLIS or name in _SHELLS or name == "uwsgi"


@dataclass
class _Reader:
    manifest: str
    resolver: _Resolver
    targets: list[Target] = field(default_factory=list)
    line: int = 0
    raw: str = ""
    auxiliary: bool = False
    #: `$@` of a script a manifest followed; None for a script read on its own.
    args: list[str] | None = None
    depth: int = 0
    chain: tuple[str, ...] = ()
    local: dict[str, str] = field(default_factory=dict)

    def home(self) -> _Where:
        """A Procfile's, or package.json's, own directory: where its commands run."""
        return _Where((posixpath.dirname(self.manifest),))

    def record(self, server: bool, found: _Resolution, *, blocking: bool | None = None) -> None:
        self.targets.append(Target(
            manifest=self.manifest, line=self.line, command=self.raw[:300], server=server,
            files=found.files, unresolved="" if found.files else found.reason,
            blocking=(not found.files) and (found.blocking if blocking is None else blocking),
            auxiliary=self.auxiliary or bool(_DEV_COMMAND.search(self.raw))))

    def block(self, reason: str) -> None:
        """Something a deployment manifest starts that is not understood: the deployment
        is unknown. In a test, CI or dev file it adds nothing and blocks nothing."""
        if not self.auxiliary:
            self.record(True, _Resolution(reason=reason, blocking=True))

    def entry_script(self, found: _Resolution, where: _Where, *, script: bool) -> None:
        """A Python file or module a manifest runs, with any application it serves by name.
        A script's own directory is first on its sys.path; for `-m` the working directory is."""
        served: list[str] = []
        opaque = ""
        for rel in found.files:
            if posixpath.basename(rel) == "__init__.py":
                continue  # imported on the way, not run as __main__
            specs, unknown = self.resolver.served(rel)
            opaque = opaque or unknown
            search = _Where((posixpath.dirname(rel),)) if script else where
            for spec in specs:
                resolution = self.resolver.module(spec.split(":", 1)[0], search)
                if not resolution.files:
                    opaque = opaque or f"{rel} serves {spec}: {resolution.reason}"
                served.extend(resolution.files)
        if served:
            found = _Resolution(tuple(dict.fromkeys((*found.files, *served))))
        self.record(bool(served), found)
        if opaque:
            self.record(True, _Resolution(reason=opaque, blocking=True))

    # ── command lines ─────────────────────────────────────────────────────────────
    def script(self, text: str, where: _Where, first_line: int, env: dict[str, str] | None = None) -> _Where:
        """A shell script, or one command string run through a shell."""
        env = dict(env or {})
        functions = {a or b for a, b in _FUNCTION.findall(text)}
        # Continuation lines are collected in a list and joined once: a long run of `\`
        # lines must not be re-concatenated (or re-split) line by line.
        pending: list[str] = []
        size, start, heredoc = 0, first_line, None
        for number, line in enumerate(text.splitlines(), first_line):
            if heredoc is not None:
                if line.strip() == heredoc:
                    heredoc = None
                continue
            if not pending:
                start = number
            continued = line.endswith("\\")
            pending.append(line[:-1] if continued else line)
            size += len(line)
            if size > _MAX_COMMAND:
                self.line, self.raw = start, pending[0][:300]
                self.block(f"a command line is longer than {_MAX_COMMAND} characters")
                pending, size = [], 0
                continue
            if continued:
                continue
            buffer = "\n".join(pending)
            words = _words(buffer)
            if words is None:
                # An open quote: a multi-line `echo "..."` is one command, not many.
                if len(pending) < 50:
                    continue
                self.line, self.raw = start, " ".join(buffer.split())
                self.block("a command line could not be split into words")
                pending, size = [], 0
                continue
            self.line, self.raw = start, " ".join(buffer.split())
            where, heredoc = self.command_line(words, where, env, functions)
            pending, size = [], 0
        if pending:
            buffer = "\n".join(pending)
            self.line, self.raw = start, " ".join(buffer.split())[:300]
            self.block("a command line could not be split into words")
        return where

    def command_line(self, words: list[str], where: _Where, env: dict[str, str],
                     functions: set[str] = frozenset()) -> tuple[_Where, str | None]:
        heredoc = None
        segment: list[str] = []
        segments: list[tuple[list[str], str]] = []
        opened = 0
        i = 0
        while i < len(words):
            word = words[i]
            if word in _SEPARATORS:
                end = word
                if word == "(":
                    opened += 1
                elif word == ")":
                    if opened:
                        opened -= 1
                    else:
                        end = "pattern"  # `start)` in a case statement
                segments.append((segment, end))
                segment = []
            elif word in ("<<", "<<-"):
                if i + 1 < len(words):
                    heredoc = words[i + 1].lstrip("-")
                i += 1
            elif _REDIRECT.match(word):
                i += 1  # the redirection's target
            else:
                segment.append(word)
            i += 1
        segments.append((segment, ""))
        for argv, end in segments:
            while argv and argv[0] in _KEYWORDS:
                argv = argv[1:]
            if not argv or end == "pattern" or argv[0] in ("case", "function", "for", "select") \
                    or (argv[0] in functions and len(argv) == 1 and end == "("):
                continue
            if argv[0] in functions:
                continue  # a call to a function this script defines: its body is read in place
            if argv[0] in ("cd", "pushd"):
                target = _expand(argv[1], self.local) if len(argv) > 1 else "~"
                where = where.enter(target, self.resolver, posixpath.dirname(self.manifest))
            elif argv[0] == "popd":
                where = replace(where, bases=None)
            elif argv[0] in ("export", "readonly", "declare", "local", "typeset") or all(_ASSIGN.match(w) for w in argv):
                for word in argv:
                    if _ASSIGN.match(word):
                        key, value = word.split("=", 1)
                        env[key] = value
                        self.local[key] = value
            else:
                self.argv(argv, where, env)
        return where, heredoc

    def argv(self, argv: list[str], where: _Where, env: dict[str, str]) -> None:
        """One simple command, split into words."""
        env = dict(env)
        argv = _expand_positionals(argv, self.args)
        i = 0
        while i < len(argv):
            word = argv[i]
            if _ASSIGN.match(word):
                key, value = word.split("=", 1)
                env[key] = value
                i += 1
            elif word in _KEYWORDS:
                i += 1
            elif word == "command" and i + 1 < len(argv) and argv[i + 1] in ("-v", "-V"):
                return  # `command -v uvicorn` looks a program up and runs nothing
            elif posixpath.basename(word) in _WRAPPERS:
                i = _skip_wrapper(argv, i, env)
            else:
                break
        if i >= len(argv):
            return
        written = argv[i]
        program = _expand(written, self.local)
        exe, args = posixpath.basename(program), argv[i + 1:]
        if not exe or _DYNAMIC.search(exe):
            if self.args is None and _POSITIONAL.match(written):
                # A script read on its own that runs its arguments (`exec "$@"`): a manifest
                # that runs it is followed with them, and a format nothing reads blocks.
                return
            self.block(f"the program {written!r} is chosen at run time")
            return
        if exe in _SHELLS:
            self.shell(args, where, env)
        elif _PYTHON.match(exe):
            self.python(args, where, env)
        elif exe in SERVERS:
            self.server(exe, args, where)
        elif exe == "uwsgi":
            self.uwsgi(args, where)
        elif exe == "fastapi":
            self.fastapi(args, where)
        elif exe == "flask":
            self.flask(args, where, env)
        elif exe in ("source", "."):
            self.source(args, where, env)
        elif "/" in program or exe.endswith((".sh", ".bash", ".py")):
            self.program_file(program, args, where, env)
        else:
            self.other(exe, args, where)

    def other(self, exe: str, args: list[str], where: _Where) -> None:
        """A program that is none of the above."""
        if exe in _SETUP_COMMANDS:
            if any(_names_program(a) for a in args):
                self.block(f"{exe} is given a program to run ({' '.join(args)[:80]})")
            return
        if exe in _NOT_APP_SERVERS:
            return
        if exe in _NODE:
            if self.resolver.python_spawns():
                self.block(f"{exe} runs JavaScript, and JavaScript here can start a Python server")
            return
        first = next((a for a in args if not a.startswith("-")), "")
        if exe in ("docker", "podman", "docker-compose"):
            if exe == "docker-compose":
                first = "compose"
                args = ["compose", *args]
            if first in ("build", "push", "pull", "login", "logout", "tag", "images", "image", "ps", "logs",
                         "stop", "rm", "rmi", "network", "volume", "inspect", "system", "info", "version",
                         "buildx", "save", "load", "kill", "wait"):
                return
            if first == "compose" and not any(a in ("-f", "--file") or a.startswith("--file=") for a in args):
                return  # the compose files it starts are read where they are
            self.block(f"{exe} {first} starts a container this reader does not follow")
            return
        if exe in ("systemctl", "service"):
            units = [a for a in args if not a.startswith("-")]
            verb, names = (units[0], units[1:]) if exe == "systemctl" and units else (
                units[1] if len(units) > 1 else "", units[:1])
            if verb not in ("start", "restart", "reload", "enable", "try-restart", "reload-or-restart", "reenable"):
                return
            if names and all(n in self.resolver.units or f"{n}.service" in self.resolver.units for n in names):
                return  # units read where they are
            self.block(f"{exe} starts {', '.join(names) or 'a unit'}, not a unit file in the repository")
            return
        if exe == "supervisorctl":
            if self.resolver.supervised:
                return
            self.block("supervisorctl starts programs no supervisord file in the repository declares")
            return
        self.block(f"{exe} is not a program this reader understands")

    def source(self, args: list[str], where: _Where, env: dict[str, str]) -> None:
        """`. venv/bin/activate` sets up the environment; a script in the repository is read."""
        if not args:
            return
        found = self.resolver.program(args[0] if "/" in args[0] else f"./{args[0]}", where, self.manifest)
        if len(found) == 1:
            self.follow(found[0], args[1:], where, env)

    def program_file(self, program: str, args: list[str], where: _Where, env: dict[str, str]) -> None:
        """A program named by a path: a script in the repository is followed."""
        found = self.resolver.program(program, where, self.manifest)
        if not found:
            self.block(f"{program} is not a file in the repository")
            return
        if len(found) > 1:
            self.block(f"{program} could be more than one file ({', '.join(found[:4])})")
            return
        rel = found[0]
        interpreter = self.resolver.shebang(rel)
        if rel.endswith(".py") or _PYTHON.match(interpreter):
            self.entry_script(self.resolver.file(rel, _Where(("",))), where, script=True)
        elif interpreter in _SHELLS or (not interpreter and rel.endswith((".sh", ".bash"))):
            self.follow(rel, args, where, env)
        else:
            self.block(f"{rel} is not a script this reader understands")

    def follow(self, rel: str, args: list[str], where: _Where, env: dict[str, str]) -> None:
        """Read a repository shell script a manifest runs, with its arguments as `$@`."""
        self.resolver.followed.add(rel)
        if rel in self.chain or rel == self.manifest:
            return  # already being read: a loop starts nothing new
        if self.depth >= _MAX_DEPTH:
            self.block(f"{rel} is nested more than {_MAX_DEPTH} scripts deep")
            return
        read = read_source(self.resolver.root, self.resolver.root / rel, self.resolver.settings.max_file_bytes)
        if read.text is None:
            self.block(f"{rel} could not be read ({read.status})")
            return
        sub = _Reader(rel, self.resolver, auxiliary=self.auxiliary, args=list(args), depth=self.depth + 1,
                      chain=(*self.chain, self.manifest))
        sub.script(read.text, where, 1, env)
        self.targets.extend(sub.targets)

    def shell(self, args: list[str], where: _Where, env: dict[str, str]) -> None:
        command, script, rest = _shell_invocation(args)
        if command is not None:
            saved, self.args = self.args, rest[1:]
            try:
                self.script(command, where, self.line, env)
            finally:
                self.args = saved
        elif script is not None:
            if _DYNAMIC.search(script):
                self.block(f"the script {script!r} is chosen at run time")
            else:
                self.program_file(script if "/" in script else f"./{script}", rest, where, env)
        else:
            self.block("a shell reads its commands from standard input")

    def python(self, args: list[str], where: _Where, env: dict[str, str]) -> None:
        j = 0
        while j < len(args):
            arg = args[j]
            if arg == "-m" or (arg.startswith("-m") and len(arg) > 2 and not arg.startswith("--")):
                module = arg[2:] if len(arg) > 2 else (args[j + 1] if j + 1 < len(args) else "")
                rest = args[j + 1:] if len(arg) > 2 else args[j + 2:]
                if not module:
                    self.block("python -m names no module")
                elif module in _MODULE_SERVERS:
                    self.server(_MODULE_SERVERS[module], rest, where)
                elif module == "fastapi":
                    self.fastapi(rest, where)
                elif module == "flask":
                    self.flask(rest, where, env)
                elif module in _SETUP_MODULES or module.split(".")[0] in _SETUP_MODULES:
                    return
                else:
                    self.entry_script(self.resolver.module(module, where, run_main=True), where, script=False)
                return
            if arg.startswith("-c"):
                code = arg[2:] if len(arg) > 2 else (args[j + 1] if j + 1 < len(args) else "")
                self.python_code(code)
                return
            if arg == "-":
                self.block("python reads its program from standard input")
                return
            if arg in ("-V", "--version", "-h", "--help"):
                return
            if arg in ("-X", "-W", "-Q"):
                j += 2
                continue
            if arg.startswith("-"):
                j += 1
                continue
            name = posixpath.basename(arg)
            if name in SERVERS:
                self.server(name, args[j + 1:], where)
            elif name in _CLIS:
                (self.fastapi(args[j + 1:], where) if name == "fastapi"
                 else self.flask(args[j + 1:], where, env))
            else:
                self.entry_script(self.resolver.file(arg, where), where, script=True)
            return
        self.block("python starts without a program (an interactive or piped interpreter)")

    def python_code(self, code: str) -> None:
        """`python -c "..."`: nothing to follow, so any sign of a server or a subprocess blocks."""
        try:
            with warnings.catch_warnings():  # the target's own SyntaxWarnings are not ours to print
                warnings.simplefilter("ignore")
                tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError):
            self.block("python -c runs code that could not be parsed")
            return
        specs, opaque = _served(tree, "python -c")
        mentions = re.search(r"\b(?:uvicorn|gunicorn|hypercorn|granian|daphne|waitress|uwsgi|cheroot"
                             r"|bjoern|werkzeug|fastapi|flask|aiohttp|runpy|importlib)\b", code)
        if specs or opaque or mentions:
            self.block("python -c runs code that may start a server")

    def server(self, exe: str, args: list[str], where: _Where) -> None:
        flags = _VALUE_FLAGS.get(exe, set())
        cwd_flags, path_flags, spec_flags = _CWD_FLAGS.get(exe, ()), _PATH_FLAGS.get(exe, ()), _SPEC_FLAGS.get(exe, ())
        cwd: list[str] = []
        paths: list[str] = []
        candidates: list[str] = []
        j = 0
        while j < len(args):
            arg = args[j]
            if arg == "--":
                candidates.extend(p for p in args[j + 1:] if _DYNAMIC.search(p) or _APP_SPEC.match(p))
                break
            if arg.startswith("-") and len(arg) > 1:
                key, eq, value = arg.partition("=")
                if key in flags and not eq:
                    value = args[j + 1] if j + 1 < len(args) else ""
                    j += 1
                if key in cwd_flags and value:
                    cwd.append(value)
                if key in path_flags and value:
                    paths.append(value)
                if key in spec_flags and value:
                    candidates.append(value)
            elif _DYNAMIC.search(arg) or _APP_SPEC.match(arg):
                candidates.append(arg)
            j += 1
        if not candidates:
            self.record(True, _Resolution(reason=f"{exe} names no application on its command line "
                                                 "(a config file or the environment does)", blocking=True))
            return
        if len(candidates) > 1:
            self.record(True, _Resolution(reason=f"{exe} has more than one application-shaped argument "
                                                 f"({', '.join(candidates[:4])})", blocking=True))
            return
        self.record(True, self.resolver.module(candidates[0].split(":", 1)[0], self._adjusted(where, cwd, paths)))

    def _adjusted(self, where: _Where, cwd: list[str], paths: list[str]) -> _Where:
        for directory in cwd:
            where = where.enter(directory, self.resolver)
        for directory in paths:
            where = where.union(where.enter(directory, self.resolver))
        return where

    def uwsgi(self, args: list[str], where: _Where) -> None:
        modules: list[str] = []
        files: list[str] = []
        cwd: list[str] = []
        paths: list[str] = []
        j = 0
        while j < len(args):
            arg = args[j]
            if not arg.startswith("-"):
                self.record(True, _Resolution(reason=f"uwsgi reads {arg} (a configuration, not read here)",
                                              blocking=True))
                return
            key, eq, value = arg.partition("=")
            if not eq and j + 1 < len(args) and not args[j + 1].startswith("-"):
                value = args[j + 1]
                j += 1
            if _UWSGI_OPAQUE.match(key) or value.endswith((".ini", ".xml", ".yaml", ".yml", ".json")):
                self.record(True, _Resolution(reason=f"uwsgi {key} loads what its command line does not name",
                                              blocking=True))
                return
            if key in _UWSGI_MODULE:
                modules.append(value)
            elif key in _UWSGI_FILE:
                files.append(value)
            elif key == "--chdir":
                cwd.append(value)
            elif key in ("--pythonpath", "--pp"):
                paths.append(value)
            j += 1
        where = self._adjusted(where, cwd, paths)
        if len(modules) + len(files) != 1:
            self.record(True, _Resolution(reason="uwsgi does not name exactly one application", blocking=True))
        elif modules:
            self.record(True, self.resolver.module(modules[0].split(":", 1)[0], where))
        else:
            self.record(True, self.resolver.file(files[0], where))

    def fastapi(self, args: list[str], where: _Where) -> None:
        positionals, entry, j = [], "", 0
        while j < len(args):
            arg = args[j]
            key, eq, value = arg.partition("=")
            if key in ("-e", "--entrypoint"):
                entry = value if eq else (args[j + 1] if j + 1 < len(args) else "")
                j += 1 if eq else 2
                continue
            if key in ("--host", "--port", "--app", "--workers", "--root-path",
                       "--forwarded-allow-ips") and not eq:
                j += 2
                continue
            if not arg.startswith("-"):
                positionals.append(arg)
            j += 1
        if not positionals or positionals[0] not in ("run", "dev"):
            return
        if entry:
            self.record(True, self.resolver.module(entry.split(":", 1)[0], where))
            return
        if len(positionals) > 2:
            self.record(True, _Resolution(reason="fastapi is given more than one path", blocking=True))
            return
        if len(positionals) > 1:
            path = positionals[1]
            if path.endswith(".py") or _DYNAMIC.search(path):
                self.record(True, self.resolver.file(path, where))
                return
            names = [f"{path.rstrip('/')}/{n}" for n in ("__init__.py", "main.py", "app.py", "api.py")]
        else:
            names = list(_FASTAPI_DEFAULTS)
        self.record(True, self._first_file(names, where, f"fastapi finds no application for {self.raw!r}"))

    def flask(self, args: list[str], where: _Where, env: dict[str, str]) -> None:
        app, j, subcommand = env.get("FLASK_APP", ""), 0, ""
        while j < len(args):
            arg = args[j]
            key, eq, value = arg.partition("=")
            if key in ("--app", "-A"):
                app = value if eq else (args[j + 1] if j + 1 < len(args) else "")
                j += 1 if eq else 2
                continue
            if key in ("-e", "--env-file", "-h", "--host", "-p", "--port", "--cert", "--key",
                       "--extra-files", "--exclude-patterns") and not eq:
                j += 2
                continue
            if not arg.startswith("-") and not subcommand:
                subcommand = arg
            j += 1
        if subcommand != "run":
            return
        if not app:
            if any(self.resolver.exists(_join(b, n) or "") for b in (where.bases or ("",))
                   for n in (".flaskenv", ".env")):
                self.record(True, _Resolution(reason="flask run takes FLASK_APP from a dotenv file",
                                              blocking=True))
                return
            self.record(True, self._first_file(list(_FLASK_DEFAULTS), where,
                                               "flask run names no application (FLASK_APP)"))
            return
        spec = app.split(":", 1)[0]
        found = (self.resolver.file(spec, where) if spec.endswith(".py") or "/" in spec
                 else self.resolver.module(spec, where))
        self.record(True, found)

    def _first_file(self, names: list[str], where: _Where, reason: str) -> _Resolution:
        """The CLI's own search: in each candidate directory the first of `names` present.
        More than one candidate directory finding different files is ambiguous."""
        rels = self.resolver.rels
        if where.bases is None:
            by_dir: dict[str, str] = {}
            for name in names:
                for hit in self.resolver._ending(name):
                    by_dir.setdefault(hit[: len(hit) - len(name)].rstrip("/"), hit)
            hits = sorted(set(by_dir.values()))
        else:
            hits = sorted({next((c for c in (_join(b, n) for n in names) if c in rels), "")
                           for b in where.bases} - {""})
        if len(hits) == 1:
            return _Resolution((hits[0],))
        if hits:
            return _ambiguous("the application", hits)
        return _Resolution(reason=reason, blocking=True)

    def run(self, value: str | list[str], where: _Where, line: int, env: dict[str, str]) -> None:
        """An exec-form list or a shell-form string."""
        if isinstance(value, list):
            self.line, self.raw = line, " ".join(value)
            self.argv(value, where, env)
        else:
            self.script(value, where, line, env)

    def entry_and_command(self, entry: tuple[int, str | list[str]] | None,
                          command: tuple[int, str | list[str]] | None, where: _Where,
                          env: dict[str, str]) -> None:
        """Docker and compose: ENTRYPOINT receives CMD as its arguments."""
        if entry is None:
            if command is not None:
                self.run(command[1], where, command[0], env)
            return
        line, value = entry
        if isinstance(value, str) or command is None:
            self.run(value, where, line, env)  # the shell form ignores CMD
            return
        arguments = command[1] if isinstance(command[1], list) else ["/bin/sh", "-c", command[1]]
        self.run(value + arguments, where, command[0], env)


def _words(text: str) -> list[str] | None:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return None


def _skip_wrapper(argv: list[str], i: int, env: dict[str, str]) -> int:
    budget = _WRAPPER_POSITIONALS.get(posixpath.basename(argv[i]), 0)
    j, after_flag = i + 1, False
    while j < len(argv):
        word = argv[j]
        name = posixpath.basename(word)
        if word == "--":
            after_flag = False
            budget = 0
        elif _ASSIGN.match(word):
            key, value = word.split("=", 1)
            env[key] = value
            after_flag = False
        elif word.startswith("-"):
            after_flag = "=" not in word
        elif _names_program(word) or name in _WRAPPERS:
            break
        elif after_flag or word.isdigit():
            after_flag = False
        elif budget:
            budget -= 1
        else:
            break
        j += 1
    return j


def _shell_invocation(args: list[str]) -> tuple[str | None, str | None, list[str]]:
    """`bash -euo pipefail -c 'cmd' name a b` -> ("cmd", None, ["name", "a", "b"]);
    `sh ./entry.sh a` -> (None, "./entry.sh", ["a"]); neither when the shell reads stdin."""
    j, command, stdin = 0, False, False
    while j < len(args):
        arg = args[j]
        if arg == "--":
            j += 1
            break
        if arg in ("--rcfile", "--init-file"):
            j += 2
            continue
        if arg.startswith("--"):
            j += 1
            continue
        if arg[:1] in "-+" and len(arg) > 1:
            letters = arg[1:]
            command = command or "c" in letters
            stdin = stdin or "s" in letters
            j += 1 + letters.count("o") + letters.count("O")  # `-o pipefail` takes a value
            continue
        break
    positionals = args[j:]
    if command:
        return (positionals[0], None, positionals[1:]) if positionals else (None, None, [])
    if stdin or not positionals:
        return None, None, []
    return None, positionals[0], positionals[1:]


# ── finding manifests ─────────────────────────────────────────────────────────────
_DOCKERFILE = re.compile(r"^(?:docker|container)file(?:[._-].*)?$")
_DOC_SUFFIXES = (".md", ".rst", ".txt", ".adoc", ".html", ".orig", ".bak", ".swp", ".dockerignore", ".json",
                 ".yml", ".yaml", ".toml", ".py", ".sh", ".lock")
_FLY = re.compile(r"^fly[._-][\w.-]+\.toml$")
_VALUES = re.compile(r"^values(?:[._-][\w.-]+)?\.ya?ml$")
#: Task runners and platform start files whose format is not read, checked lexically.
_SCRIPT_NAMES = frozenset({"makefile", "gnumakefile", "justfile", ".justfile", "startup.txt", "web.config"})
_SCRIPT_SUFFIXES = (".mk", ".cmd", ".bat", ".ps1", ".bicep")


def _kind(name: str) -> str | None:
    lower = name.lower()
    if lower in _UNREAD_NAMES or lower.startswith("ecosystem.config.") or lower.startswith("pm2.config."):
        return "unread"
    for suffix in _TEMPLATE_SUFFIXES:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            inner = _kind(name[: -len(suffix)])
            if inner in ("systemd", "docker", "compose", "procfile", "unread", "shell"):
                return "unread"
            return "unread-template" if inner is not None else None
    if lower.endswith(".service"):
        return "systemd"
    if (_DOCKERFILE.match(lower) and not lower.endswith(_DOC_SUFFIXES)) or lower.endswith((".dockerfile", ".containerfile")):
        return "docker"
    if _FLY.match(lower):
        return "unread"
    if _COMPOSE.match(lower):
        return "compose"
    if lower == "procfile" or lower.startswith("procfile."):
        return "procfile"
    if name == "package.json":
        return "package"
    if lower.endswith((".conf", ".ini")):
        return "supervisor"
    if lower.endswith((".sh", ".bash")):
        return "shell"
    if _VALUES.match(lower):
        return "unread-values"
    if lower.endswith((".yaml", ".yml")):
        return "unread-yaml"
    if lower in _SCRIPT_NAMES or lower.endswith(_SCRIPT_SUFFIXES):
        return "unread-script"
    if lower.endswith((".tf", ".hcl", ".nomad")):
        return "unread-hcl"
    if lower.endswith(".json"):
        return "unread-json"
    if name == "Jenkinsfile":
        return "unread-ci"
    return None


_CONTENT_KINDS = frozenset({"unread-yaml", "unread-hcl", "unread-json", "unread-template", "unread-ci",
                            "unread-values", "unread-script"})


def _auxiliary(rel: str, kind: str) -> bool:
    """Tests, CI, examples, dev tooling or a package.json script: never the deployment."""
    parts = rel.split("/")
    return (kind == "package" or any(p.lower() in _AUXILIARY_DIRS for p in parts[:-1])
            or bool(_AUXILIARY_NAME.search(parts[-1])))


def _inert(rel: str) -> bool:
    """Test data, examples, docs or editor setup: formats found there deploy nothing."""
    parts = rel.split("/")
    return any(p.lower() in _INERT_DIRS for p in parts[:-1]) or bool(_AUXILIARY_NAME.search(parts[-1]))


def _outside(path: Path, root: Path) -> bool:
    try:
        return not Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(root)))
    except (OSError, ValueError):
        return True


def _manifest_paths(s: ScanSettings) -> list[tuple[str, str]]:
    root, skip = s.root, SkipRule(s.skip_parts)
    found: list[tuple[str, str]] = []

    def unreadable(error: OSError) -> None:
        # A directory that cannot be listed may hold a manifest: not silently skipped.
        try:
            rel = Path(error.filename).relative_to(root).as_posix()
        except (TypeError, ValueError):
            rel = ""
        if rel and not skip.matches(tuple(rel.split("/"))) and not _inert(rel + "/x"):
            found.append((rel, "unlisted"))

    for parent, directories, files in os.walk(root, onerror=unreadable, followlinks=False):
        here = Path(parent)
        kept = []
        for d in sorted(directories):
            rel = (here / d).relative_to(root)
            if skip.matches(rel.parts):
                continue
            if (here / d).is_symlink():
                # A linked directory inside the root is walked where it really is; one that
                # leaves the root may hold manifests this reader will not follow.
                if _outside(here / d, root) and not _inert(rel.as_posix() + "/x"):
                    found.append((rel.as_posix(), "symlink"))
                continue
            kept.append(d)
        directories[:] = kept
        for directory in directories:
            if directory.lower() in _UNREAD_DIRS:
                found.append(((here / directory).relative_to(root).as_posix(), "unread"))
        for name in sorted(files):
            kind = _kind(name)
            if here.name.lower().endswith(".service.d"):
                kind = "unread"  # a systemd drop-in overrides a unit's ExecStart
            if not kind:
                continue
            rel = (here / name).relative_to(root).as_posix()
            if (here / name).is_symlink():
                # Read where it really is, unless that is outside the root or not a name
                # this reader looks at.
                if (_outside(here / name, root) or not _kind(Path(os.path.realpath(here / name)).name)) \
                        and not _inert(rel):
                    found.append((rel, "symlink"))
                continue
            if kind in _CONTENT_KINDS:
                if _CI_FILE.search(rel):
                    kind = "unread-ci"
                elif _inert(rel):
                    continue  # a Kubernetes fixture under tests/ deploys nothing
            found.append((rel, kind))
    # Compose files first: a Dockerfile a service builds is read there, with its context.
    return sorted(found, key=lambda item: item[1] != "compose")


def _lexical_line(path: Path, patterns: tuple[re.Pattern[bytes], ...],
                  requires: tuple[re.Pattern[bytes], re.Pattern[bytes]] | None = None) -> int | None:
    """The line where any of `patterns` first matches (or, for `requires`, where the second
    matches in a file the first matches), 0 when none does, None when the file cannot be
    read in full within the bound. Bytes, in overlapping chunks: size and encoding do not
    matter."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except OSError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        try:
            info = os.fstat(stream.fileno())
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > _LEXICAL_CAP:
            return None
        chunk_size, overlap = 1 << 20, 4096
        offset_lines, tail = 0, b""
        needed = {id(p): False for p in (requires or ())}
        first_required_line = 0
        while True:
            try:
                chunk = stream.read(chunk_size)
            except OSError:
                return None
            if not chunk and not tail:
                break
            data = tail + chunk
            for pattern in patterns:
                match = pattern.search(data)
                if match:
                    return offset_lines + data.count(b"\n", 0, match.start()) + 1
            if requires:
                first, second = requires
                if first.search(data):
                    needed[id(first)] = True
                match = second.search(data)
                if match and not first_required_line:
                    first_required_line = offset_lines + data.count(b"\n", 0, match.start()) + 1
                if needed[id(first)] and first_required_line:
                    return first_required_line
            if not chunk:
                break
            # Keep the last `overlap` bytes, cut at a line start so `^` still anchors.
            cut = data.rfind(b"\n", 0, max(0, len(data) - overlap))
            cut = cut + 1 if cut >= 0 else max(0, len(data) - overlap)
            offset_lines += data.count(b"\n", 0, cut)
            tail = data[cut:]
    return 0


_CONTENT_PATTERNS: dict[str, tuple[re.Pattern[bytes], ...]] = {
    "unread-yaml": (_UNREAD_YAML, _CI_DEPLOY, _SERVER_LINE),
    "unread-values": (_VALUES_COMMAND, _UNREAD_YAML),
    "unread-script": (_SERVER_LINE, _CI_DEPLOY, _START_COMMAND),
    "unread-hcl": (_UNREAD_HCL,),
    "unread-json": (_UNREAD_JSON,),
    "unread-template": (_UNREAD_TEMPLATE, _UNREAD_YAML, _UNREAD_HCL, _UNREAD_JSON),
    "unread-ci": (_CI_DEPLOY, _UNREAD_YAML),
    "supervisor": (_UNREAD_INI,),
    "shell": (_CI_DEPLOY,),
}


def _unread(rel: str, line: int, why: str = "") -> Target:
    return Target(manifest=rel, line=line, command="", server=True, blocking=True,
                  unresolved=why or f"{rel} is a deployment format this reader does not interpret")


# ── manifest readers ──────────────────────────────────────────────────────────────
def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines with trailing-backslash continuations joined, numbered by their first line."""
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        elif line.lstrip().startswith("#"):
            continue  # Docker drops comment lines inside a continuation
        part = line.strip()
        if part.endswith("\\"):
            pending.append(part[:-1].rstrip())
            continue
        pending.append(part)
        out.append((start, " ".join(p for p in pending if p) if len(pending) > 1 else part))
        pending = []
    if pending:
        out.append((start, " ".join(p for p in pending if p)))
    return out


def _systemd(reader: _Reader, text: str) -> None:
    workdir, env = "", {}
    starts: list[tuple[int, str]] = []
    for number, line in _logical_lines(text):
        if not line or line[0] in "#;":
            continue
        key, eq, value = line.partition("=")
        if not eq:
            continue
        key, value = key.strip(), value.strip()
        if key == "WorkingDirectory":
            workdir = value.lstrip("-")
        elif key == "ExecStart" and value:
            starts.append((number, value.lstrip("-@:+!|")))
        elif key == "Environment":
            env.update(w.split("=", 1) for w in (_words(value) or []) if _ASSIGN.match(w))
    where = _Where()  # a system unit starts in `/`: unknown unless WorkingDirectory says
    if workdir and workdir != "~":
        where = where.enter(workdir, reader.resolver)
    for number, command in starts:
        reader.script(command, where, number, env)


def _exec_or_shell(value: str) -> str | list[str]:
    value = value.strip()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
        except ValueError:
            return value
        if isinstance(parsed, list) and all(isinstance(v, str) for v in parsed):
            return parsed
    return value


#: Images whose own default command cannot serve this repository's Python application: a
#: bare OS or interpreter image (a shell or a REPL) and common backing services. A final
#: Dockerfile stage or a compose service with no command of its own runs the image's.
_INERT_IMAGES = frozenset({
    "python", "pypy", "debian", "ubuntu", "alpine", "busybox", "scratch", "node", "postgres",
    "postgis/postgis", "mysql", "mariadb", "redis", "valkey/valkey", "memcached", "nginx", "caddy",
    "traefik", "haproxy", "envoyproxy/envoy", "rabbitmq", "mongo", "minio/minio"})


def _image_name(ref: str) -> str:
    """`docker.io/library/python:3.12-slim@sha256:...` -> `python`; "" when the repository
    part is substituted at build time (`${BASE}`)."""
    ref = ref.strip().strip("\"'").split("@", 1)[0]
    head, _, last = ref.rpartition("/")
    if ":" in last:
        last = last[: last.index(":")]
    parts = [*(head.split("/") if head else []), last]
    if not last or any(_DYNAMIC.search(part) for part in parts):
        return ""
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    if len(parts) > 1 and parts[0] == "library":
        parts = parts[1:]
    return "/".join(parts).lower()


@dataclass
class _Stage:
    workdir: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    entry: tuple[int, str | list[str]] | None = None
    command: tuple[int, str | list[str]] | None = None
    #: The CMD came from the stage this one is built FROM (an ENTRYPOINT here resets it).
    inherited_command: bool = False
    copies: list[tuple[str, tuple[str, ...] | None]] = field(default_factory=list)
    #: The external image the stage chain starts FROM, as written.
    base: str = ""

    def image(self) -> _Image:
        return _Image(tuple(self.copies))


_GLOB = re.compile(r"[*?\[]")


def _copy(value: str, stage: _Stage, contexts: tuple[str, ...], resolver: _Resolver,
          stages: dict[str, _Stage]) -> list[tuple[str, tuple[str, ...] | None]]:
    """What one COPY/ADD puts where: image path -> repository paths (None: not from here)."""
    words = _exec_or_shell(value)
    words = words if isinstance(words, list) else (_words(value) or [])
    flags = [w for w in words if w.startswith("--")]
    args = [w for w in words if not w.startswith("--")]
    if "<<" in value:
        return [(posixpath.normpath(posixpath.join(stage.workdir, args[-1])), None)] if args else []
    if len(args) < 2:
        return []
    *sources, dest = args
    into_dir = dest.endswith("/") or len(sources) > 1 or dest in (".", "./")
    dest = posixpath.normpath(dest if dest.startswith("/") else posixpath.join(stage.workdir, dest))
    origin = next((f.split("=", 1)[1] for f in flags if f.startswith("--from=")), None)
    out: list[tuple[str, tuple[str, ...] | None]] = []
    for source in sources:
        name = posixpath.basename(source.rstrip("/"))
        if origin is not None:
            other = stages.get(origin.lower())
            found = None
            if other is not None:
                path = source if source.startswith("/") else posixpath.join(other.workdir, source)
                found = other.image().resolve(path, resolver)
            if found is None:
                out.append((posixpath.join(dest, name) if into_dir else dest, None))
                continue
            for repo in found:
                out.append((posixpath.join(dest, name) if into_dir and resolver.is_file(repo) else dest, (repo,)))
            continue
        if "://" in source or source.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            out.append((posixpath.join(dest, name) if into_dir else dest, None))
            continue
        if _GLOB.search(source):
            literal = posixpath.dirname(source.split("*")[0].split("?")[0].split("[")[0])
            repos = tuple(j for j in (_join(c, literal) for c in contexts) if j is not None and resolver.is_dir(j))
            out.append((dest, repos or None))
            continue
        repos = [j for j in (_join(c, source) for c in contexts) if j is not None and resolver.exists(j)]
        if not repos:
            out.append((posixpath.join(dest, name) if into_dir else dest, None))
            continue
        for repo in repos:
            if resolver.is_dir(repo):
                out.append((dest, (repo,)))
            else:
                out.append((posixpath.join(dest, name) if into_dir else dest, (repo,)))
    return out


def _docker_stages(text: str, contexts: tuple[str, ...], resolver: _Resolver) -> list[_Stage]:
    stages: list[_Stage] = []
    by_name: dict[str, _Stage] = {}
    current: _Stage | None = None
    for number, line in _logical_lines(text):
        if not line or line.startswith("#"):
            continue
        instruction, _, value = line.partition(" ")
        instruction = instruction.upper()
        if instruction == "FROM":
            words = [w for w in value.split() if not w.startswith("--")]
            parent = by_name.get(words[0].lower()) if words else None
            current = _Stage(base=words[0] if words else "")
            if parent is not None:
                current = _Stage(parent.workdir, dict(parent.env), parent.entry, parent.command,
                                 parent.command is not None, list(parent.copies), parent.base)
            stages.append(current)
            by_name[str(len(stages) - 1)] = current
            if len(words) >= 3 and words[1].upper() == "AS":
                by_name[words[2].lower()] = current
        elif current is None:
            continue
        elif instruction == "WORKDIR":
            value = value.strip().strip('"')
            current.workdir = posixpath.normpath(value if value.startswith("/") else posixpath.join(current.workdir, value))
        elif instruction == "ENV":
            words = _words(value) or []
            if words and not _ASSIGN.match(words[0]) and len(words) > 1:
                current.env[words[0]] = " ".join(words[1:])
            else:
                current.env.update(w.split("=", 1) for w in words if _ASSIGN.match(w))
        elif instruction == "CMD":
            current.command, current.inherited_command = (number, _exec_or_shell(value)), False
        elif instruction == "ENTRYPOINT":
            # ENTRYPOINT resets only a CMD inherited from the base image; a CMD defined in
            # this stage, before or after it, stays its default arguments (Dockerfile
            # reference, "Understand how CMD and ENTRYPOINT interact").
            current.entry = (number, _exec_or_shell(value))
            if current.inherited_command:
                current.command, current.inherited_command = None, False
        elif instruction in ("COPY", "ADD"):
            current.copies.extend(_copy(value, current, contexts, resolver, by_name))
    return stages


def _stage_where(stage: _Stage, resolver: _Resolver, workdir: str | None = None) -> _Where:
    image = stage.image()
    return _Where(image.resolve(workdir or stage.workdir, resolver, directory=True), image)


def _dockerfile(reader: _Reader, text: str) -> None:
    if reader.manifest in reader.resolver.built and not reader.auxiliary:
        return  # a compose service builds it, and read it with the real build context
    folder = posixpath.dirname(reader.manifest)
    # `docker build -f dir/Dockerfile .` is as common as building in `dir`: both contexts.
    contexts = tuple(dict.fromkeys((folder, "")))
    stages = _docker_stages(text, contexts, reader.resolver)
    for stage in stages:
        reader.entry_and_command(stage.entry, stage.command, _stage_where(stage, reader.resolver), stage.env)
    if stages and stages[-1].entry is None and stages[-1].command is None:
        _base_command(reader, stages[-1].base)


def _base_command(reader: _Reader, base: str) -> None:
    """An image with no ENTRYPOINT or CMD of its own runs its base image's, which is not in
    the repository, unless that base cannot serve a Python application at all."""
    if _image_name(base) not in _INERT_IMAGES:
        reader.block(f"the image runs the command of its base image {base or '(none)'}, which is not in the repository")


def _strip_yaml_comment(line: str) -> str:
    quote = ""
    for i, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _flow_list(text: str) -> list[str]:
    inner = text.strip()[1:-1]
    items, current, quote = [], "", ""
    for char in inner:
        if quote:
            if char == quote:
                quote = ""
            else:
                current += char
        elif char in "\"'":
            quote = char
        elif char == ",":
            items.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        items.append(current.strip())
    return items


def _yaml_value(lines: list[str], i: int, indent: int, value: str) -> tuple[str | list[str], int]:
    """The value of `key: value` at line `i`, and the index of the next unread line."""
    j = i + 1
    if value.startswith("["):
        parts, depth = [value], value.count("[") - value.count("]")
        while depth > 0 and j < len(lines):
            part = _strip_yaml_comment(lines[j]).strip()
            parts.append(part)
            depth += part.count("[") - part.count("]")
            j += 1
        if depth > 0:
            raise ValueError("an unterminated flow sequence")
        return _flow_list(" ".join(parts)), j
    deeper: list[str] = []
    while j < len(lines):
        line = _strip_yaml_comment(lines[j]).rstrip()
        if line.strip():
            at = len(line) - len(line.lstrip(" "))
            # `command:` followed by `- uvicorn` at the same indent is still its sequence.
            if at < indent or (at == indent and (value or not line.lstrip().startswith("-"))):
                break
        deeper.append(line)
        j += 1
    if value[:1] in (">", "|"):
        texts = [line.strip() for line in deeper if line.strip()]
        return (" ".join(texts) if value[0] == ">" else "\n".join(texts)), j
    if not value:
        items = [_unquote(line.strip()[1:]) for line in deeper if line.strip().startswith("-")]
        if any(line.strip() and not line.strip().startswith("-") for line in deeper):
            raise ValueError("a mapping where a command was expected")
        return (items if items else ""), j
    return _unquote(value), i + 1


#: YAML the line reader below cannot follow: anchors merged or aliased into a service, a
#: service extending another, another compose file included.
_COMPOSE_OPAQUE = re.compile(r"^[ \t]*<<[ \t]*:|:[ \t]+\*[\w.-]+[ \t]*\r?$|^[ \t]*-[ \t]+\*[\w.-]+[ \t]*\r?$"
                             r"|^[ \t]+extends[ \t]*:|^include[ \t]*:", re.MULTILINE)


_SERVICE_HEADER = re.compile(r"""^(?:"[^"]+"|'[^']+'|[\w.-]+)[ \t]*:$""")
_SERVICE_KEYS = re.compile(r"^[ \t]+[\"']?(?:command|entrypoint|image|build)[\"']?[ \t]*:", re.MULTILINE)


def _compose(reader: _Reader, text: str) -> None:
    """Block-style compose YAML, read line by line. Anything else in the `services` mapping
    (flow style, a service header with a value, odd indentation) raises ValueError, which
    the caller turns into a blocking target."""
    opaque = _COMPOSE_OPAQUE.search(text)
    if opaque:
        reader.line = text.count("\n", 0, opaque.start()) + 1
        reader.block(f"{reader.manifest} uses YAML anchors, extends or include, which this reader does not follow")
        return
    lines = text.splitlines()
    services: list[dict] = []
    in_services, service_indent, key_indent, service, in_build = False, None, None, None, False
    saw_services, open_key = False, False
    i = 0
    while i < len(lines):
        line = _strip_yaml_comment(lines[i]).rstrip()
        if not line.strip() or line.strip() == "---":
            i += 1
            continue
        if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
            raise ValueError("tab indentation")
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if indent == 0:
            top, _, rest = content.partition(":")
            in_services, service_indent, service = _unquote(top) == "services", None, None
            if in_services:
                saw_services = True
                if rest.strip() not in ("", "{}"):
                    raise ValueError("services written in flow style")
            i += 1
            continue
        if not in_services:
            i += 1
            continue
        if service_indent is None:
            service_indent = indent
        if indent <= service_indent:
            if indent < service_indent or not _SERVICE_HEADER.match(content):
                raise ValueError("a service entry this reader cannot follow")
            service = {"line": i + 1, "name": _unquote(content[:-1])}
            services.append(service)
            key_indent, in_build, open_key = None, False, False
            i += 1
            continue
        if key_indent is None:
            key_indent = indent
        if indent < key_indent:
            raise ValueError("inconsistent indentation in a service")
        key, colon, value = content.partition(":")
        if indent > key_indent:
            name = _unquote(key)
            if in_build and name in ("context", "dockerfile", "target"):
                service[name] = _unquote(value)
            elif in_build and name == "dockerfile_inline":
                service["dockerfile_inline"] = True
            i += 1
            continue
        if content.startswith("-"):
            if not open_key:
                raise ValueError("a sequence where a service key was expected")
            i += 1  # an indentless sequence under the previous key (`ports:` then `- 80:80`)
            continue
        if not colon:
            raise ValueError("a service key this reader cannot follow")
        key, value = _unquote(key), value.strip()
        open_key = not value
        in_build = key == "build"
        if key == "build":
            service["build"] = True
            if value:
                service["context"] = _unquote(value)
            i += 1
        elif key == "image":
            service["image"] = _unquote(value)
            i += 1
        elif key in ("command", "entrypoint", "working_dir"):
            parsed, i_next = _yaml_value(lines, i, indent, value)
            service[key] = (i + 1, parsed)
            open_key = False
            i = i_next
        else:
            i += 1
    if not saw_services and _SERVICE_KEYS.search(text):
        raise ValueError("services outside a top-level services mapping")
    folder = posixpath.dirname(reader.manifest)
    resolver = reader.resolver
    for service in services:
        reader.line, reader.raw = service["line"], ""
        stage: _Stage | None = None
        if service.get("build"):
            context = _join(folder, service.get("context") or ".")
            dockerfile = _join(context or "", service.get("dockerfile") or "Dockerfile") if context is not None else None
            if context is not None and dockerfile is not None and resolver.is_file(dockerfile) \
                    and not service.get("dockerfile_inline"):
                read = read_source(resolver.root, resolver.root / dockerfile, resolver.settings.max_file_bytes)
                if read.text is not None:
                    stages = _docker_stages(read.text, (context,), resolver)
                    stage = stages[-1] if stages else None
                    if service.get("target"):
                        stage = _named_stage(read.text, stages, service["target"]) or stage
                    if not reader.auxiliary:
                        resolver.built.add(dockerfile)
        entry, command = service.get("entrypoint"), service.get("command")
        if entry is not None and command is None:
            command = None  # compose: an entrypoint clears the image's default command
        elif stage is not None:
            entry = entry if entry is not None else stage.entry
            command = command if command is not None else stage.command
        if entry is None and command is None:
            if service.get("build") and stage is None:
                reader.block(f"service {service['name']} builds an image whose Dockerfile is not in the "
                             "repository, so its command is not known")
            elif stage is not None:
                _base_command(reader, stage.base)
            elif service.get("image"):
                if _image_name(service["image"]) not in _INERT_IMAGES:
                    reader.block(f"service {service['name']} runs image {service['image']}, so its command is not known")
            else:
                reader.block(f"service {service['name']} names no image, build or command")
            continue
        working = service.get("working_dir")
        if stage is not None:
            where = _stage_where(stage, resolver, working[1] if working and isinstance(working[1], str) else None)
        else:
            where = _Where()
            if working and isinstance(working[1], str):
                where = where.enter(working[1], resolver)
        if isinstance(entry, tuple) and isinstance(entry[1], str) and command is not None:
            entry = (entry[0], _words(entry[1]) or [])
        reader.entry_and_command(entry, command, where, dict(stage.env) if stage else {})


def _named_stage(text: str, stages: list[_Stage], target: str) -> _Stage | None:
    names = [m.group(1).lower() for m in re.finditer(r"^\s*FROM\s+(?:--\S+\s+)*\S+\s+AS\s+(\S+)", text,
                                                    re.MULTILINE | re.IGNORECASE)]
    froms = [m for m in re.finditer(r"^\s*FROM\s", text, re.MULTILINE | re.IGNORECASE)]
    if len(froms) != len(stages):
        return None
    for index, match in enumerate(froms):
        line = text[match.start(): text.find("\n", match.start()) if "\n" in text[match.start():] else len(text)]
        alias = re.search(r"\sAS\s+(\S+)", line, re.IGNORECASE)
        if alias and alias.group(1).lower() == target.lower() and target.lower() in names:
            return stages[index]
    return None


def _procfile(reader: _Reader, text: str) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*[\w.-]+\s*:\s*(.+)$", line)
        if match and not line.lstrip().startswith("#"):
            reader.script(match.group(1), reader.home(), number)


def _package_json(reader: _Reader, text: str) -> None:
    try:
        scripts = json.loads(text).get("scripts") or {}
    except (ValueError, AttributeError):
        return
    if not isinstance(scripts, dict):
        return
    first: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        for match in re.finditer(r'"([^"\\]*)"', line):
            first.setdefault(match.group(1), number)
    for name, command in scripts.items():
        if not isinstance(command, str):
            continue
        reader.script(command, reader.home(), first.get(name, 0))


def _supervisor(reader: _Reader, text: str) -> None:
    program, entries = False, {}
    blocks: list[dict] = []
    key = ""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("["):
            program = bool(re.match(r"^\[(fcgi-)?program:", stripped))
            entries, key = {}, ""
            if program:
                blocks.append(entries)
            continue
        if not program:
            continue
        if line[:1] in " \t" and key in entries:
            number0, value = entries[key]
            entries[key] = (number0, f"{value} {stripped}")
            continue
        name, eq, value = stripped.partition("=")
        # A line without `=` (`autorestart` alone) sets nothing: it must not become the key
        # an indented continuation is appended to.
        key = name.strip() if eq else ""
        if eq:
            entries[key] = (number, value.strip())
    for entries in blocks:
        if "command" not in entries:
            continue
        where = _Where()  # supervisord's own working directory, unless `directory=` says
        if "directory" in entries:
            where = where.enter(entries["directory"][1], reader.resolver)
        env = {}
        if "environment" in entries:
            for part in re.split(r",(?=\s*[A-Za-z_]\w*=)", entries["environment"][1]):
                name, eq, value = part.strip().partition("=")
                if eq:
                    env[name] = _unquote(value)
        reader.script(entries["command"][1], where, entries["command"][0], env)


def _shell(reader: _Reader, text: str) -> None:
    # A script run on its own starts in a directory nobody knows.
    reader.script(text, _Where(), 1)


_READERS = {"systemd": _systemd, "docker": _dockerfile, "compose": _compose, "procfile": _procfile,
            "package": _package_json, "supervisor": _supervisor, "shell": _shell}


def discover(s: ScanSettings, python_rels: list[str] | tuple[str, ...], modules: ModuleMap) -> Deployment:
    """Every Python process the repository's deployment manifests start."""
    resolver = _Resolver(s, python_rels, modules)
    paths = _manifest_paths(s)
    if len(paths) > MAX_MANIFESTS:
        return Deployment((), (Target(manifest="", line=0, command="", server=True,
                                      unresolved=f"more than {MAX_MANIFESTS} candidate manifests",
                                      blocking=True),))
    resolver.units = {posixpath.basename(rel) for rel, kind in paths if kind == "systemd"}
    manifests: list[str] = []
    targets: list[Target] = []
    shells: list[str] = []
    for rel, kind in paths:
        if kind == "shell":
            shells.append(rel)  # after everything else: a script a manifest follows is read there
            continue
        _read_manifest(s, resolver, rel, kind, manifests, targets)
    for rel in shells:
        if rel not in resolver.followed:
            _read_manifest(s, resolver, rel, "shell", manifests, targets)
    return Deployment(tuple(manifests), tuple(targets))


def _read_manifest(s: ScanSettings, resolver: _Resolver, rel: str, kind: str, manifests: list[str],
                   targets: list[Target]) -> None:
    auxiliary = _auxiliary(rel, kind)
    if kind in ("symlink", "unlisted"):
        manifests.append(rel)
        why = ("a symlink to outside the repository (or to a file of another name), which this reader "
               "does not follow" if kind == "symlink" else "a directory that could not be listed")
        targets.append(_unread(rel, 0, f"{rel} is {why}"))
        return
    if kind == "unread":
        if posixpath.basename(rel).lower() == "app.json" and any(
                (s.root / posixpath.dirname(rel) / name).is_file() for name in ("Procfile", "procfile")):
            return  # Heroku runs the Procfile beside it, and that is read
        manifests.append(rel)
        targets.append(_unread(rel, 0))
        return
    path = s.root / rel
    if kind in _CONTENT_KINDS or kind == "supervisor" or (kind == "shell" and auxiliary and not _inert(rel)):
        patterns = _CONTENT_PATTERNS[kind]
        requires = (_YAML_SERVICES, _YAML_PROCESS) if kind in ("unread-yaml", "unread-template", "unread-values") else None
        line = _lexical_line(path, patterns, requires)
        if line is None:
            if kind in _CONTENT_KINDS or kind == "shell":
                manifests.append(rel)
                targets.append(_unread(rel, 0, f"{rel} could not be checked for a deployment (too large "
                                               "or unreadable)"))
                return
        elif line:
            manifests.append(rel)
            why = (f"{rel} deploys from CI or a tooling script, to something this reader does not follow"
                   if kind in ("unread-ci", "shell") else "")
            targets.append(_unread(rel, line, why))
            return
        if kind in _CONTENT_KINDS:
            return
    if kind == "supervisor":
        if _lexical_line(path, (_SUPERVISOR_PROGRAM,)) == 0:
            return
    read = read_source(s.root, path, s.max_file_bytes)
    reader = _Reader(rel, resolver, auxiliary=auxiliary)
    if read.text is None:
        manifests.append(rel)
        targets.append(Target(manifest=rel, line=0, command="", server=True,
                              unresolved=f"the manifest could not be read ({read.status})", blocking=True))
        return
    if kind == "supervisor":
        resolver.supervised = True
    manifests.append(rel)
    try:
        _READERS[kind](reader, read.text)
    except Exception as exc:  # noqa: BLE001 - whatever the reader trips on, the deployment is unknown
        reader.targets.append(Target(manifest=rel, line=0, command="", server=True,
                                     unresolved=f"the manifest could not be parsed ({type(exc).__name__})",
                                     blocking=True))
    seen: set[tuple] = set()
    for target in reader.targets:
        key = (target.manifest, target.line, target.files, target.unresolved, target.server, target.auxiliary)
        if key not in seen:
            seen.add(key)
            targets.append(target)
