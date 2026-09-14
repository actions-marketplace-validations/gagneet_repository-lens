"""Deployment detection fails closed, on every layout the deployment audit probed.

`[scan] deployment_detection` is on by default and LOWERS a finding's priority ("undeployed",
P3) for a route file only non-deployed applications reach. Anything a manifest does that is
not fully understood must therefore leave the deployment unknown, so nothing is demoted.

Each probe is a repository with two FastAPI applications that each serve an unauthenticated
POST (`app/main.py`, `legacy/server.py`), usually a Procfile running `app.main:app`, and the
manifest under test. The expected value is the set of route files that SHOULD be demoted.
"""
from __future__ import annotations

import builtins
import os
import random
import string
import tempfile
import textwrap
import time
import unittest
import warnings
from pathlib import Path

from repolens.config import load_config
from repolens.scan import deploy, security
from repolens.scan.settings import from_config
from repolens.scan.wiring import ModuleMap

APP = textwrap.dedent("""
    from fastapi import FastAPI
    app = FastAPI()

    @app.post("/upload")
    async def upload(d: dict):
        return d
""")
BASE = {"app/__init__.py": "", "app/main.py": APP, "legacy/__init__.py": "", "legacy/server.py": APP}
KNOWN = {"Procfile": "web: uvicorn app.main:app --port $PORT\n"}
LEGACY = {"legacy/server.py"}
NONE: set[str] = set()


class Link(str):
    """A symlink to this target (relative to the link's directory)."""


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, text in {"repolens.toml": '[scan]\npython_roots = ["."]\n', **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, Link):
            os.symlink(str(text), path)
        elif isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8", newline="")


def demoted(files: dict[str, str | bytes]) -> set[str]:
    """Route files the security check marks undeployed; deployment discovery must not raise.
    The repository is `<tmp>/repo`, so `../outside/...` entries land outside its root."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        _write(root, files)
        s = from_config(load_config(str(root)))
        rels = [rel for rel in files if rel.endswith(".py")]
        deploy.discover(s, rels, ModuleMap(rels, s.python_roots))
        return {f.file for f in security.scan(s)
                if f.rule == "security/unauthenticated-mutation-route" and f.exposure == "undeployed"}


def known(extra: dict[str, str | bytes], manifest: dict[str, str] | None = None) -> dict[str, str | bytes]:
    return {**BASE, **(KNOWN if manifest is None else manifest), **extra}


SERVICE = "[Service]\nExecStart={}\n"
PKGUTIL = {
    "app/__init__.py": "",
    "app/main.py": "import importlib, pkgutil\nfrom fastapi import FastAPI\nimport app.routers as r\napp = FastAPI()\n"
                   "for m in pkgutil.iter_modules(r.__path__):\n    app.include_router(importlib.import_module(f'app.routers.{m.name}').router)\n",
    "app/routers/__init__.py": "",
    "app/routers/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/items')\nasync def c(d: dict):\n    return d\n",
    "old/__init__.py": "", "old/main.py": "from fastapi import FastAPI\nfrom app.routers import items\napp = FastAPI()\napp.include_router(items.router)\n",
    "Procfile": "web: uvicorn app.main:app\n"}

#: (label, repository, route files that must be demoted)
PROBES: list[tuple[str, dict[str, str | bytes], set[str]]] = [
    ("baseline: the Procfile runs only app.main", known({}), LEGACY),
    # A program or application this reader cannot name.
    ("gunicorn -c config naming wsgi_app", known({"deploy/api.service": SERVICE.format("/opt/venv/bin/gunicorn -c gunicorn.conf.py"),
                                                  "gunicorn.conf.py": "wsgi_app = 'legacy.server:app'\n"}), NONE),
    ("gunicorn application factory", known({"deploy/api.service": SERVICE.format("/opt/venv/bin/gunicorn 'legacy.server:create_app()'")}), NONE),
    ("sh -c with a runtime module", known({"Dockerfile": 'FROM python\nCMD ["sh","-c","uvicorn $MODULE"]\n'}), NONE),
    ("an extensionless start script", known({"Dockerfile": 'FROM python\nENTRYPOINT ["./start"]\n',
                                             "start": "#!/bin/sh\nexec uvicorn legacy.server:app\n"}), NONE),
    ("a start script under docker/ with a WORKDIR", known({"docker/Dockerfile": 'FROM python\nWORKDIR /srv\nCOPY . .\nENTRYPOINT ["./docker/start.sh"]\n',
                                                          "docker/start.sh": "#!/bin/sh\ncd /srv\nexec uvicorn legacy.server:app\n"}), NONE),
    ("compose command as a list", known({"docker-compose.yml": "services:\n  api:\n    build: .\n    command:\n      - uvicorn\n      - legacy.server:app\n"}), NONE),
    ("compose merge key", known({"docker-compose.yml": "x-api: &api\n  command: uvicorn legacy.server:app\n  build: .\nservices:\n  api:\n    <<: *api\n"}), NONE),
    ("compose image-only service", known({"docker-compose.yml": "services:\n  api:\n    image: registry.example/api:latest\n"}), NONE),
    ("multi-stage build inheriting WORKDIR", known({"Dockerfile": "FROM python AS base\nWORKDIR /srv/legacy\nFROM base AS final\nCMD uvicorn server:app\n"}), NONE),
    ("Procfile running bin/start", known({"bin/start": "#!/bin/sh\nexec uvicorn legacy.server:app\n"},
                                         {"Procfile": "web: bin/start\nadmin: uvicorn app.main:app\n"}), NONE),
    ("hypercorn with --root-path", known({"deploy/h.service": SERVICE.format("/venv/bin/hypercorn --root-path /api -b 0.0.0.0:80 legacy.server:app")}), NONE),
    ("systemd python -m on a package", known({"deploy/h.service": SERVICE.format("/opt/venv/bin/python -m legacy"),
                                              "legacy/__main__.py": "import uvicorn\nuvicorn.run('legacy.server:app')\n"}), NONE),
    ("systemd script outside the repository", known({"deploy/h.service": SERVICE.format("/opt/service/bin/run-api")}), NONE),
    ("a dynamic interpreter", known({"deploy/run.sh": "#!/bin/sh\n$PYTHON -m uvicorn legacy.server:app\n"}), NONE),
    ("CMD make run", known({"Dockerfile": 'FROM python\nCMD ["make","run"]\n', "Makefile": "run:\n\tuvicorn legacy.server:app\n"}), NONE),
    ("node spawning a Python server", known({"Dockerfile": 'FROM node\nCMD ["node","server.js"]\n',
                                             "server.js": "require('child_process').spawn('uvicorn',['legacy.server:app'])\n"}), NONE),
    ("a console script", known({"Dockerfile": 'FROM python\nCMD ["service-api"]\n',
                                "pyproject.toml": "[project]\nname='x'\n[project.scripts]\nservice-api='legacy.cli:main'\n",
                                "legacy/cli.py": "import uvicorn\ndef main():\n    uvicorn.run('legacy.server:app')\n"}), NONE),
    ("bash -o pipefail -c", known({"Dockerfile": 'FROM python\nCMD ["bash","-o","pipefail","-c","uvicorn legacy.server:app"]\n'}), NONE),
    ("bash -eu -o pipefail -c", known({"Dockerfile": 'FROM python\nCMD ["bash","-eu","-o","pipefail","-c","uvicorn legacy.server:app"]\n'}), NONE),
    ("sh with a script path outside the image copy", known({"Dockerfile": 'FROM python\nCMD ["sh","/srv/entry"]\n', "entry": "uvicorn legacy.server:app\n"}), NONE),
    # Servers started from Python.
    ("uvicorn.Config naming the app", known({"deploy/api.service": SERVICE.format("/venv/bin/python serve.py"),
                                             "serve.py": "import uvicorn\nconfig = uvicorn.Config('legacy.server:app', port=9000)\nuvicorn.Server(config).run()\n"}), NONE),
    ("an aliased uvicorn import", known({"deploy/api.service": SERVICE.format("/venv/bin/python serve.py"),
                                         "serve.py": "import uvicorn as uv\nuv.run('legacy.server:app')\n"}), NONE),
    ("a subprocess starting the server", known({"deploy/api.service": SERVICE.format("/venv/bin/python serve.py"),
                                                "serve.py": "import subprocess\nsubprocess.run(['uvicorn','legacy.server:app'])\n"}), NONE),
    # Which file a module name means.
    ("COPY api/ . with a root main.py", {"main.py": APP, "api/main.py": APP,
                                         "Dockerfile": "FROM python\nWORKDIR /app\nCOPY api/ .\nCMD uvicorn main:app\n"}, NONE),
    ("an unmapped systemd WorkingDirectory", {"main.py": APP, "service/main.py": APP,
                                              "deploy/api.service": "[Service]\nWorkingDirectory=/opt/api/current\nExecStart=/opt/venv/bin/uvicorn main:app\n"}, NONE),
    ("compose naming a Dockerfile in a subdirectory", {"main.py": APP, "api/main.py": APP,
                                                       "docker-compose.yml": "services:\n  api:\n    build:\n      context: .\n      dockerfile: api/Dockerfile\n    command: uvicorn main:app\n"}, NONE),
    ("WORKDIR /app filled from srv/, beside an unrelated app/", {"app/__init__.py": "", "app/main.py": APP, "srv/main.py": APP,
                                                                  "Dockerfile": 'FROM python\nWORKDIR /app\nCOPY srv/ /app/\nCMD ["uvicorn", "main:app"]\n'}, {"app/main.py"}),
    # Deployment formats this reader does not interpret.
    ("Vercel", known({"vercel.json": '{"rewrites":[{"source":"/(.*)","destination":"/api/index"}]}', "api/index.py": APP}), NONE),
    ("SAM template", known({"template.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nTransform: AWS::Serverless-2016-10-31\nResources:\n  Api:\n    Type: AWS::Serverless::Function\n    Properties:\n      Handler: legacy.handler.handler\n      Runtime: python3.12\n",
                            "legacy/handler.py": "from mangum import Mangum\nfrom legacy.server import app\nhandler = Mangum(app)\n"}), NONE),
    ("Azure Functions", known({"host.json": '{"version":"2.0"}',
                               "function_app.py": "import azure.functions as func\nfrom legacy.server import app as fa\napp = func.AsgiFunctionApp(app=fa, http_auth_level=func.AuthLevel.ANONYMOUS)\n"}), NONE),
    ("Cloud Foundry manifest", known({"manifest.yml": "applications:\n- name: api\n  command: uvicorn legacy.server:app --port $PORT\n"}), NONE),
    ("Terraform Lambda", known({"infra/main.tf": 'resource "aws_lambda_function" "api" {\n  handler = "legacy.handler.handler"\n  runtime = "python3.12"\n}\n'}), NONE),
    ("Terraform app command line", known({"infra/main.tf": 'resource "azurerm_linux_web_app" "api" {\n  site_config {\n    app_command_line = "gunicorn -k uvicorn.workers.UvicornWorker legacy.server:app"\n  }\n}\n'}), NONE),
    ("Cloud Build run deploy --command", known({"cloudbuild.yaml": "steps:\n- name: gcr.io/cloud-builders/gcloud\n  args: ['run','deploy','api','--command','uvicorn','--args','legacy.server:app']\n"}), NONE),
    ("Kubernetes JSON", known({"deploy/k8s/deployment.json": '{"kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"api","command":["uvicorn","legacy.server:app"]}]}}}}'}), NONE),
    ("templated Kubernetes YAML", known({"deploy/k8s/deployment.yaml.j2": 'kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: api\n          command: ["uvicorn", "{{ module }}"]\n'}), NONE),
    ("templated supervisor config", known({"deploy/supervisor.conf.j2": "[program:api]\ncommand={{ venv }}/bin/uvicorn {{ app_module }}\n"}), NONE),
    ("Kubernetes YAML over max_file_bytes", known({"deploy/k8s/all.yaml": "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: api\n          command: [uvicorn, legacy.server:app]\n" + "# pad\n" * 400_000}), NONE),
    ("Kubernetes YAML under scripts/", known({"scripts/deploy/k8s.yaml": "spec:\n  containers:\n    - name: api\n      command: [uvicorn, legacy.server:app]\n"}), NONE),
    ("a CI workflow deploying over ssh", known({".github/workflows/deploy.yml": "jobs:\n  deploy:\n    steps:\n      - run: ssh prod 'cd /srv && nohup uvicorn legacy.server:app &'\n"}), NONE),
    ("pm2 ecosystem file", known({"ecosystem.config.js": "module.exports={apps:[{name:'api',script:'uvicorn',args:'legacy.server:app',interpreter:'none'}]}\n"}), NONE),
    ("circus.ini", known({"deploy/circus.ini": "[watcher:api]\ncmd = uvicorn legacy.server:app\n"}), NONE),
    ("uwsgi --module", known({"deploy/api.service": SERVICE.format("/venv/bin/uwsgi --http :80 --module legacy.server:app")}), NONE),
    ("waitress-serve", known({"deploy/api.service": SERVICE.format("/venv/bin/waitress-serve --port=80 legacy.server:app")}), NONE),
    ("an option value containing a colon", known({"deploy/api.service": SERVICE.format("/venv/bin/gunicorn --dogstatsd-tags env:prod legacy.server:app"),
                                                  "env.py": ""}), NONE),
    ("an entrypoint receiving CMD", known({"Dockerfile": 'FROM python\nENTRYPOINT ["/docker-entrypoint.sh"]\nCMD ["uvicorn","legacy.server:app"]\n'}), NONE),
    ("a production Dockerfile beside a dev one", known({"Dockerfile.prod": 'FROM python\nCMD ["uvicorn","legacy.server:app"]\n',
                                                        "Dockerfile.dev": 'FROM python\nCMD ["uvicorn","app.main:app","--reload"]\n'}, {}), NONE),
    ("a compose override file", known({"docker-compose.override.yml": "services:\n  api:\n    command: uvicorn legacy.server:app\n"}), NONE),
    # Parsing.
    ("supervisor: a bare key, a continuation, then command=", known({"deploy/supervisord.conf": "[program:api]\nautorestart\n    true\ncommand=uvicorn app.main:app\n"},
                                                                    {"Procfile": "web: uvicorn app.main:app\n"}), LEGACY),
    ("a Flask factory beside an unmounted router", {**known({}, {"Procfile": "web: gunicorn 'app.main:app'\n"}),
                                                    "web/__init__.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app\n",
                                                    "web/views.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/x')\nasync def x(d: dict):\n    return d\n"}, LEGACY),
    ("a binary Dockerfile", known({"Dockerfile": b"\x00\x01FROM\xff"}), NONE),
    ("invalid UTF-8 Kubernetes YAML", known({"deploy/k8s.yaml": b"containers:\n  - \xff\xfe\n"}), NONE),
    ("a 5,000-deep JSON exec form", known({"Dockerfile": "FROM python\nCMD " + "[" * 5000 + "]" * 5000 + "\n"}), NONE),
    ("a 100,000-deep package.json", known({"package.json": "[" * 100_000 + "]" * 100_000}), NONE),
    ("a supervisor continuation before any key", known({"deploy/s.conf": "[program:a]\n  continued\ncommand=uvicorn legacy.server:app\n"}), NONE),
    ("a shell script with an unbalanced quote", known({"deploy/run.sh": 'echo "\n' + "uvicorn legacy.server:app\n" * 60}), NONE),
    # Compose YAML the line reader cannot follow blocks (A-DEP-1); common shapes still read.
    ("a compose command that does not parse", known({"docker-compose.yml": "services:\n command: [\n  - x\n"}), NONE),
    ("a compose service in flow style", known({"docker-compose.yml": 'services:\n  api: {build: ., command: "uvicorn legacy.server:app"}\n',
                                               "Dockerfile": "FROM python\nCOPY . .\nCMD uvicorn app.main:app\n"}), NONE),
    ("a quoted compose command key", known({"docker-compose.yml": 'services:\n  api:\n    build: .\n    "command": uvicorn legacy.server:app\n',
                                            "Dockerfile": "FROM python\nCOPY . .\nCMD uvicorn app.main:app\n"}), NONE),
    ("a compose service naming no image, build or command", known({"docker-compose.yml": "services:\n  api:\n    ports: ['80:80']\n"}), NONE),
    ("a compose file without a services mapping", known({"docker-compose.yml": "api:\n  build: .\n  command: uvicorn legacy.server:app\n"}), NONE),
    ("an indentless compose command sequence", known({"docker-compose.yml": "services:\n  api:\n    build: .\n    command:\n    - uvicorn\n    - legacy.server:app\n",
                                                      "Dockerfile": "FROM python\nCOPY . .\nCMD uvicorn app.main:app\n"}), NONE),
    ("an indentless compose ports sequence", known({"docker-compose.yml": "services:\n  api:\n    build: .\n    ports:\n    - '8000:8000'\n",
                                                    "Dockerfile": "FROM python\nWORKDIR /app\nCOPY . .\nCMD uvicorn app.main:app\n"}, {}), LEGACY),
    ("CRLF YAML with an image-only service", known({"deploy/stack.yml": "services:\r\n  api:\r\n    image: registry.example/api\r\n"}), NONE),
    # Images whose command is not in the repository (A-DEP-3, A-DEP-12).
    ("a Dockerfile with no CMD on an application-server base", known({"Dockerfile": "FROM registry.example/asgi-server:1\nCOPY ./legacy /app\n"}), NONE),
    ("a Dockerfile with no CMD FROM a build argument", known({"Dockerfile": "ARG BASE=registry.example/asgi\nFROM ${BASE}\nCOPY . /app\n"}), NONE),
    ("a Dockerfile with no CMD on a plain python base", known({"Dockerfile": "FROM python:3.12-slim\nCOPY . /app\n"}), LEGACY),
    ("a final stage inheriting a plain base", known({"Dockerfile": "FROM docker.io/library/python:3.12 AS build\nRUN true\nFROM build\nCOPY . /app\n"}), LEGACY),
    ("compose with a postgres service", known({"docker-compose.yml": "services:\n  api:\n    build: .\n    depends_on: [db]\n  db:\n    image: postgres:16\n",
                                               "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCMD uvicorn app.main:app\n"}, {}), LEGACY),
    ("a Procfile beside a database-only compose file", known({"docker-compose.yml": "services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7\n"}), LEGACY),
    ("compose with an nginx proxy", known({"docker-compose.yml": "services:\n  api:\n    build: .\n  proxy:\n    image: nginx:1.27\n",
                                           "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCMD uvicorn app.main:app\n"}, {}), LEGACY),
    # More names and formats (A-DEP-4).
    ("Dockerfile-prod", known({"Dockerfile-prod": "FROM python\nCOPY . .\nCMD uvicorn legacy.server:app\n"}), NONE),
    ("docker/Dockerfile_api", known({"docker/Dockerfile_api": "FROM python\nCOPY . .\nCMD uvicorn legacy.server:app\n"}), NONE),
    ("a Dockerfile.md document", known({"Dockerfile.md": "CMD uvicorn legacy.server:app\n"}), LEGACY),
    ("a systemd drop-in", known({"deploy/api.service.d/override.conf": "[Service]\nExecStart=\nExecStart=/venv/bin/uvicorn legacy.server:app\n"}), NONE),
    ("a systemd unit template (.service.in)", known({"deploy/api.service.in": "[Service]\nExecStart=@bindir@/uvicorn legacy.server:app\n"}), NONE),
    ("fly.production.toml", known({"fly.production.toml": "app = 'api'\n[processes]\n  app = 'uvicorn legacy.server:app'\n"}), NONE),
    ("an App Engine service file", known({"backend.yaml": "runtime: python312\nservice: backend\nentrypoint: gunicorn legacy.server:app\n"}), NONE),
    ("Helm values without a chart", known({"deploy/values.yaml": "image:\n  repository: registry.example/api\nargs: [uvicorn, legacy.server:app]\n"}), NONE),
    ("Kubernetes YAML in flow style", known({"deploy/k8s.yaml": "kind: Deployment\nspec: {template: {spec: {containers: [{name: api, command: [uvicorn, legacy.server:app]}]}}}\n"}), NONE),
    ("an Ansible task starting the server", known({"ansible/roles/api/tasks/main.yml": "- name: start api\n  shell: nohup /opt/venv/bin/gunicorn legacy.server:app &\n"}), NONE),
    ("a Taskfile", known({"Taskfile.yml": "version: '3'\ntasks:\n  prod:\n    cmds:\n      - gunicorn legacy.server:app\n"}), NONE),
    ("a Makefile production target", known({"Makefile": "run-prod:\n\tgunicorn -k uvicorn.workers.UvicornWorker legacy.server:app\n"}), NONE),
    ("a Makefile deploying over ssh", known({"Makefile": "deploy:\n\tssh prod 'systemctl restart api'\n"}), NONE),
    ("a Makefile development target", known({"Makefile": "dev:\n\tuvicorn legacy.server:app --reload\n"}), LEGACY),
    ("a conda environment listing server packages", known({"environment.yml": "dependencies:\n  - uvicorn=0.30.1\n  - gunicorn>=21\n"}), LEGACY),
    ("web.config", known({"web.config": '<configuration><httpPlatform processPath="python.exe" arguments="-m uvicorn legacy.server:app"/></configuration>\n'}), NONE),
    ("startup.cmd", known({"startup.cmd": "@echo off\r\npython -m uvicorn legacy.server:app --port 8000\r\n"}), NONE),
    ("startup.txt", known({"startup.txt": "gunicorn -k uvicorn.workers.UvicornWorker legacy.server:app\n"}), NONE),
    ("a PowerShell start script", known({"deploy/run.ps1": "& python -m uvicorn legacy.server:app\n"}), NONE),
    ("Bicep appCommandLine", known({"infra/app.bicep": "resource web 'Microsoft.Web/sites@2022-03-01' = {\n  properties: { siteConfig: { appCommandLine: startCommand } }\n}\n"}), NONE),
    # Symlinks (A-DEP-6).
    ("a unit linked from outside the root", known({"../outside/api.service": SERVICE.format("/venv/bin/uvicorn legacy.server:app"),
                                                   "deploy/api.service": Link("../../outside/api.service")}), NONE),
    ("a manifest directory linked from outside the root", known({"../outside_k8s/api.yaml": "spec:\n  containers:\n    - command: [uvicorn, legacy.server:app]\n",
                                                                 "k8s": Link("../outside_k8s")}), NONE),
    ("a Dockerfile linked to a file of another name", known({"docker/api.real": "FROM python\nWORKDIR /app\nCOPY . .\nCMD uvicorn legacy.server:app\n",
                                                             "Dockerfile": Link("docker/api.real")}), NONE),
    ("a compose file linked to another compose file", known({"deploy/compose.yml": "services:\n  api:\n    image: python:3.12\n    command: uvicorn app.main:app\n",
                                                             "docker-compose.yml": Link("deploy/compose.yml")}), LEGACY),
    ("a start script reached through a linked directory", known({"../outside_bin/start": "#!/bin/sh\nexec uvicorn legacy.server:app\n", "bin": Link("../outside_bin")},
                                                                {"Procfile": "web: uvicorn app.main:app\nw2: bin/start\n"}), NONE),
    # Run scripts that move the import path (A-DEP-7).
    ("uvicorn.run with app_dir", known({"serve.py": "import uvicorn\nuvicorn.run('server:app', app_dir='svc')\n", "server.py": APP, "svc/server.py": APP},
                                       {"Procfile": "web: uvicorn app.main:app\nworker: python serve.py\n"}), NONE),
    ("a run script inserting into sys.path", known({"serve.py": "import sys, uvicorn\nsys.path.insert(0, 'svc')\nuvicorn.run('server:app')\n", "server.py": APP, "svc/server.py": APP},
                                                   {"Procfile": "web: uvicorn app.main:app\nworker: python serve.py\n"}), NONE),
    ("a run script changing directory", known({"serve.py": "import os, uvicorn\nos.chdir('svc')\nuvicorn.run('server:app')\n", "server.py": APP, "svc/server.py": APP},
                                              {"Procfile": "web: uvicorn app.main:app\nworker: python serve.py\n"}), NONE),
    # Paths the OS refuses behave like any missing path (A-DEP-8).
    ("a program path longer than a file name", known({}, {"Procfile": "web: uvicorn app.main:app\nw2: ./" + "a" * 300 + "\n"}), NONE),
    ("a cd into a path longer than a file name", known({}, {"Procfile": "web: cd " + "a" * 300 + " && uvicorn app.main:app\n"}), LEGACY),
    ("a COPY source longer than a file name", known({"Dockerfile": "FROM python\nCOPY " + "a" * 300 + " /app\nCMD uvicorn app.main:app\n"}), LEGACY),
    ("a python file longer than a file name", known({}, {"Procfile": "web: uvicorn app.main:app\nw2: python " + "a" * 300 + ".py\n"}), NONE),
    # Modules imported at run time (A-DEP-2).
    ("routers loaded through pkgutil and importlib", PKGUTIL, NONE),
    ("a constant relative import_module", {**PKGUTIL, "app/main.py": "import importlib\nfrom fastapi import FastAPI\napp = FastAPI()\n"
                                                                     "app.include_router(importlib.import_module('.items', 'app.routers').router)\n",
                                           "legacy/__init__.py": "", "legacy/server.py": APP}, LEGACY),
    ("a run script importing its app by an undotted constant", known({"serve.py": "import importlib, uvicorn\nmod = importlib.import_module('server')\nuvicorn.run(mod.app)\n",
                                                                      "server.py": APP},
                                                                     {"Procfile": "web: uvicorn app.main:app\nworker: python serve.py\n"}), LEGACY),
]

class DeploymentProbeTests(unittest.TestCase):
    def test_every_probe_layout(self):
        for label, files, expected in PROBES:
            with self.subTest(label):
                self.assertEqual(demoted(files), expected)

    def test_routers_found_at_run_time_are_not_called_unreachable(self):
        files = {k: v for k, v in PKGUTIL.items() if not k.startswith("old/") and k != "Procfile"}
        with tempfile.TemporaryDirectory() as tmp:
            _write(Path(tmp), files)
            s = from_config(load_config(tmp))
            exposures = {f.file: f.exposure for f in security.scan(s)
                         if f.rule == "security/unauthenticated-mutation-route"}
        self.assertEqual(exposures, {"app/routers/items.py": "unauthenticated"})

    def test_nothing_is_opened_through_a_directory_that_leaves_the_root(self):
        opened: list[str] = []
        real_open, real_os_open = builtins.open, os.open

        def spy_open(path, *args, **kwargs):
            opened.append(os.path.realpath(str(path)))
            return real_open(path, *args, **kwargs)

        def spy_os_open(path, *args, **kwargs):
            if not kwargs.get("dir_fd"):
                opened.append(os.path.realpath(str(path)))
            return real_os_open(path, *args, **kwargs)

        files = known({"../outside_bin/start": "#!/bin/sh\nexec uvicorn legacy.server:app\n", "bin": Link("../outside_bin")},
                      {"Procfile": "web: uvicorn app.main:app\nw2: bin/start\n"})
        builtins.open, os.open = spy_open, spy_os_open
        try:
            self.assertEqual(demoted(files), NONE)
        finally:
            builtins.open, os.open = real_open, real_os_open
        self.assertEqual([p for p in opened if "outside_bin" in p], [])

    def test_python_dash_c_code_with_an_invalid_escape_prints_no_warning(self):
        files = known({}, {"Procfile": "web: uvicorn app.main:app\nw2: python -c \"print('\\\\d')\"\n"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            demoted(files)
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, SyntaxWarning)], [])

    def test_long_lines_stay_linear(self):
        with tempfile.TemporaryDirectory() as tmp:
            rsync = Path(tmp) / "deploy.yml"
            rsync.write_bytes(b"run: rsync " + b"a " * 50_000 + b"\n")
            started = time.monotonic()
            deploy._lexical_line(rsync, deploy._CONTENT_PATTERNS["unread-ci"])
            deploy._logical_lines("RUN a \\\n" * 80_000)
            deploy._yaml_value(["    command: ["] + ["      a," for _ in range(20_000)] + ["    ]"], 0, 4, "[")
            demoted(known({"package.json": '{"scripts": {' + ",".join(f'"s{i}": "echo {i}"' for i in range(5_000)) + "}}"}))
        self.assertLess(time.monotonic() - started, 5)

    def test_random_manifests_never_raise(self):
        rng = random.Random(1)
        alphabet = string.printable + "[]{}\"'$`\\:=-#|<>&;"
        for kind in ("Dockerfile", "docker-compose.yml", "Procfile", "deploy/a.service", "deploy/s.conf",
                     "deploy/r.sh", "package.json"):
            for _ in range(8):
                text = "".join(rng.choice(alphabet) for _ in range(rng.randint(10, 400)))
                text = {"deploy/s.conf": "[program:x]\ncommand=", "deploy/a.service": "[Service]\nExecStart="}.get(kind, "") + text
                with self.subTest(kind=kind, text=text[:60]):
                    demoted(known({kind: text}))


if __name__ == "__main__":
    unittest.main()
