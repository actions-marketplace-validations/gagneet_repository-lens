"""Import local SARIF 2.1.0 results without invoking their producing tools.

Locations are display metadata only: no source file, URL or external property file
referenced by a SARIF document is opened. Unmappable locations keep their findings.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import unquote, urljoin, urlsplit

from ..core.findings import Finding, ToolRun

MAX_SARIF_BYTES = 20_000_000
MAX_RESULTS = 100_000


def _object(value, context: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"SARIF {context} must be an object")
    return value


def _list(value, context: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"SARIF {context} must be an array")
    return value


def _text(message: dict, rule: dict, driver: dict) -> str:
    value = message.get("text") or message.get("markdown")
    if not value and message.get("id"):
        if not isinstance(message["id"], str):
            raise ValueError("SARIF message id must be a string")
        for owner in (rule, driver):
            strings = _object(owner.get("messageStrings", {}), "messageStrings")
            item = _object(strings.get(message["id"], {}), "message string")
            value = item.get("text") or item.get("markdown")
            if value:
                break
    if not isinstance(value, str) or not value:
        raise ValueError("SARIF result is missing a usable message")
    arguments = message.get("arguments", [])
    if arguments:
        _list(arguments, "message arguments")
        # SARIF uses numbered substitutions, not Python format specifications.
        value = re.sub(r"\{(\d+)\}", lambda match: str(arguments[int(match[1])])
                       if int(match[1]) < len(arguments) else match[0], value)
    return value


def _location(result: dict, run: dict, root: Path) -> tuple[str, int, str]:
    locations = _list(result.get("locations", []), "locations")
    if not locations:
        return "", 0, "No physical location supplied by the producer."
    physical = _object(locations[0], "location").get("physicalLocation", {})
    physical = _object(physical, "physicalLocation")
    artifact = _object(physical.get("artifactLocation", {}), "artifactLocation")
    if "index" in artifact and "uri" not in artifact:
        index = artifact["index"]
        artifacts = _list(run.get("artifacts", []), "artifacts")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(artifacts):
            raise ValueError("SARIF artifact index is out of range")
        artifact = _object(_object(artifacts[index], "artifact").get("location", {}), "artifact location")
    uri = artifact.get("uri", "")
    if not isinstance(uri, str):
        raise ValueError("SARIF artifact URI must be a string")
    base_id = artifact.get("uriBaseId")
    if base_id is not None and not isinstance(base_id, str):
        raise ValueError("SARIF uriBaseId must be a string")
    if base_id:
        # Resolve nested base IDs without fetching anything and reject cycles.
        bases = _object(run.get("originalUriBaseIds", {}), "originalUriBaseIds")
        seen = set()
        while base_id in bases:
            if base_id in seen:
                raise ValueError("SARIF URI base cycle")
            seen.add(base_id)
            base = _object(bases[base_id], "URI base")
            base_uri = base.get("uri", "")
            if not isinstance(base_uri, str):
                raise ValueError("SARIF URI base must contain a string URI")
            uri = urljoin(base_uri, uri)
            base_id = base.get("uriBaseId")
            if base_id is not None and not isinstance(base_id, str):
                raise ValueError("SARIF uriBaseId must be a string")
        if base_id:
            return "", 0, "SARIF URI base is unresolved; finding retained without a repository location."
    parsed = urlsplit(uri)
    path_text = unquote(parsed.path).replace("\\", "/")
    region = _object(physical.get("region", {}), "region")
    line = region.get("startLine", 0)
    if not isinstance(line, int) or isinstance(line, bool) or line < 0:
        raise ValueError("SARIF startLine must be a non-negative integer")
    if (parsed.scheme not in {"", "file"} or parsed.netloc or parsed.query or parsed.fragment
            or not path_text or ".." in PurePosixPath(path_text).parts
            or any(ord(char) < 32 for char in path_text)):
        return "", 0, "SARIF location is outside the repository or is not a local source path."
    path = Path(path_text)
    if path.is_absolute():
        try:
            # Pure path arithmetic, with no dereference or read of this location.
            path_text = path.relative_to(root).as_posix()
        except ValueError:
            return "", 0, "SARIF absolute location could not be mapped to this repository."
    if ":" in path_text:
        return "", 0, "SARIF drive-qualified location could not be mapped to this repository."
    return path_text.removeprefix("./"), line, "Imported SARIF; producer evidence has not been independently verified."


def import_sarif(path: Path, root: Path) -> list[ToolRun]:
    """Convert every run, or raise on a malformed/incomplete unsupported document."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_SARIF_BYTES + 1)
    if len(raw) > MAX_SARIF_BYTES:
        raise ValueError("SARIF file exceeds the 20 MB import limit")
    payload = _object(json.loads(raw), "document")
    if payload.get("version") != "2.1.0":
        raise ValueError("only SARIF version 2.1.0 is supported")
    output = []
    total = 0
    for source in _list(payload.get("runs"), "runs"):
        source = _object(source, "run")
        tool = _object(source.get("tool"), "tool")
        driver = _object(tool.get("driver"), "driver")
        name = driver.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("SARIF driver requires a name")
        run = ToolRun(f"sarif:{name}")
        if "results" not in source:
            run.error = "SARIF producer did not supply results; analysis completeness is unknown."
        if source.get("externalPropertyFileReferences"):
            # Do not turn an external-results pointer into a zero-findings success.
            raise ValueError("external SARIF property files are not supported; export a self-contained file")
        for invocation in _list(source.get("invocations", []), "invocations"):
            invocation = _object(invocation, "invocation")
            if invocation.get("executionSuccessful") is False:
                run.error = "SARIF producer reported an unsuccessful execution."
            if any(_object(n, "notification").get("level") == "error"
                   for n in _list(invocation.get("toolExecutionNotifications", []), "notifications")):
                run.error = "SARIF producer reported an error notification."
        rules = _list(driver.get("rules", []), "rules")
        by_id = {}
        for raw_rule in rules:
            rule = _object(raw_rule, "rule")
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError("SARIF rule requires a non-empty string id")
            if rule_id in by_id:
                raise ValueError(f"duplicate SARIF rule id: {rule_id}")
            by_id[rule_id] = rule
        results = _list(source.get("results", []), "results")
        total += len(results)
        if total > MAX_RESULTS:
            raise ValueError("SARIF exceeds the 100000 result import limit")
        for result in results:
            result = _object(result, "result")
            kind = result.get("kind")
            if kind is not None and not isinstance(kind, str):
                raise ValueError("SARIF result kind must be a string")
            if kind in {"pass", "notApplicable"}:
                continue
            rule_id = result.get("ruleId")
            if rule_id is not None and not isinstance(rule_id, str):
                raise ValueError("SARIF rule ID must be a string")
            rule = by_id.get(rule_id, {})
            if "ruleIndex" in result:
                index = result["ruleIndex"]
                if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(rules):
                    raise ValueError("SARIF ruleIndex is out of range")
                rule = rules[index]
                if rule_id and rule.get("id") != rule_id:
                    raise ValueError("SARIF ruleId and ruleIndex disagree")
                rule_id = rule.get("id")
            rule_id = rule_id or "unidentified-rule"
            if not isinstance(rule_id, str):
                raise ValueError("SARIF rule ID must be a string")
            default_configuration = _object(rule.get("defaultConfiguration", {}), "defaultConfiguration")
            level = result.get("level", default_configuration.get("level", "warning"))
            if not isinstance(level, str):
                raise ValueError("SARIF level must be a string")
            if level not in {"error", "warning", "note", "none"}:
                raise ValueError("SARIF level must be error, warning, note or none")
            properties = {**_object(rule.get("properties", {}), "rule properties"),
                          **_object(result.get("properties", {}), "result properties")}
            severity = {"error": "high", "warning": "medium", "note": "info", "none": "info"}[level]
            security_score = properties.get("security-severity")
            category = "correctness"
            if security_score is not None:
                if isinstance(security_score, bool):
                    raise ValueError("invalid SARIF security-severity")
                try:
                    score = float(security_score)
                except (TypeError, ValueError) as exc:
                    raise ValueError("invalid SARIF security-severity") from exc
                if not 0 <= score <= 10:
                    raise ValueError("SARIF security-severity must be between 0 and 10")
                severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
                category = "security"
            raw_confidence = properties.get("confidence", "medium")
            confidence = raw_confidence.lower() if isinstance(raw_confidence, str) else "medium"
            if confidence not in {"high", "medium", "low"}:
                confidence = "medium"
            file, line, evidence = _location(result, source, root.resolve())
            if result.get("suppressions"):
                evidence += " Producer suppression metadata is present; the finding is retained for review."
            run.findings.append(Finding(
                tool=run.tool, rule=f"{name}/{rule_id}", severity=severity,
                confidence=confidence, category=category, file=file, line=line,
                message=_text(_object(result.get("message"), "message"), rule, driver),
                evidence=evidence, remedy="Review the producer's rule documentation and the source evidence.",
            ))
        output.append(run)
    return output
