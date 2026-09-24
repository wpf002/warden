"""Detection proposals. Phase 6: the closest defensible thing to "learning new attack vectors".

Triggers
  * an analyst confirms a true positive on an anomaly.* case (no rule named it)
  * an analyst flags a case or a set of events with "this should be its own rule"
  * an ATT&CK technique with detection guidance has no rule in the registry (intel gap)

Pipeline
  evidence -> anonymize -> Claude writes {detection, playbook, fixture, test}
  -> static checks (AST: imports allowlist, banned calls, class shape)
  -> sandbox: copy the repo to a temp dir, add the files, run the new test, the eval suites,
     and the new rule over every stored and fixture event to count what else it fires on
  -> review queue on /proposals (admin) -> approve opens a PR on a branch. Never hot-loaded.
"""
from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update

from . import db
from .config import settings

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- model output schema
class ExpectedAlertSpec(BaseModel):
    rule: str = Field(description="the new detection id")
    match_user: str = Field("", description="optional: a user the alert must name")
    match_host: str = Field("", description="optional: a host the alert must name")
    label: str = Field(description="true_positive or false_positive")


# Structured output constrains free-form objects to {} (no declared properties), so events
# travel as JSON Lines text and are parsed and validated here.
class FixtureSpec(BaseModel):
    events_jsonl: str = Field(description="Warden JSON events, one per line, each with 'kind' and 'ts'; "
                                          "the positive and at least one near-miss")
    expected_alerts: list[ExpectedAlertSpec] = Field(description="one entry per alert the positive should raise")
    description: str = Field(description="one sentence: what the positive is and what the near-miss is")

    @property
    def events(self) -> list[dict]:
        out = []
        for line in self.events_jsonl.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


class ProposalDraft(BaseModel):
    detection_id: str = Field(description="new snake_case rule id")
    mitre: list[str]
    rationale: str = Field(description="why this rule, what it catches, what it deliberately ignores")
    fixture: FixtureSpec = Field(description="complete; the evidence as a positive plus at least one near-miss")
    test_code: str = Field(description="complete pytest module for tests/test_proposed_<id>.py; never a placeholder")
    detection_code: str = Field(description="complete Python module for warden/detections/<id>.py")
    playbook_markdown: str = Field(description="complete markdown for data/knowledge/playbook-<id-with-hyphens>.md")


# ---------------------------------------------------------------- anonymization
class Anonymizer:
    """Stable pseudonyms per run: the model sees structure (same user twice is the same
    pseudonym), never real names, hosts, or addresses. The mapping is not stored."""

    KEEP_USERS = {"system", "local service", "network service", "administrator", "guest", "$", "-", ""}

    def __init__(self):
        self.maps: dict[str, dict[str, str]] = {"user": {}, "host": {}, "ip": {}, "domain": {}}

    def _p(self, kind: str, v: str, fmt: str) -> str:
        m = self.maps[kind]
        if v not in m:
            m[v] = fmt.format(len(m) + 1)
        return m[v]

    def user(self, v: str) -> str:
        if (v or "").lower() in self.KEEP_USERS or (v or "").startswith("S-1-5-") and len(v) < 12:
            return v
        if v.endswith("$") and len(v) > 1:      # a machine account stays recognisably a machine account
            return self._p("user", v, "machine-{:02d}") + "$"
        return self._p("user", v, "user-{:02d}")

    def host(self, v: str) -> str:
        return self._p("host", v.lower(), "host-{:02d}") if v else v

    def ip(self, v: str) -> str:
        if not v:
            return v
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return v
        from .detections._network import is_internal
        n = len(self.maps["ip"]) + 1
        return self.maps["ip"].setdefault(v, f"10.99.{n // 250}.{n % 250}" if is_internal(v) else f"203.0.113.{n % 250}")

    def text(self, s: str) -> str:
        for kind, fn in (("user", self.user), ("host", self.host)):
            for real, fake in sorted(self.maps[kind].items(), key=lambda kv: -len(kv[0])):
                if real and len(real) > 2:
                    s = re.sub(re.escape(real), fake, s, flags=re.I)
        return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lambda m: self.ip(m.group(0)), s)

    def event(self, e) -> dict:
        d = json.loads(e.model_dump_json(exclude={"raw"}))
        for k in ("user", "target_user"):
            if d.get(k):
                d[k] = self.user(d[k])
        if d.get("host"):
            d["host"] = self.host(d["host"])
        for k in ("source_ip", "dest_ip"):
            if d.get(k):
                d[k] = self.ip(d[k])
        for k in ("command_line", "parent_command_line", "target", "path", "resource", "domain"):
            if d.get(k):
                d[k] = self.text(d[k])
        d.pop("entity_ids", None)
        return {k: v for k, v in d.items() if v not in ("", None, [], {}, 0) or k in ("kind", "ts")}


# ---------------------------------------------------------------- static checks
ALLOWED_IMPORTS = {"__future__", "collections", "datetime", "re", "statistics", "math", "ipaddress", "typing",
                   "..events", "..models", "..config", ".", "._burst", "._identity", "._endpoint", "._network", "._cloud"}
BANNED_NAMES = {"open", "exec", "eval", "compile", "__import__", "globals", "locals", "vars", "input", "breakpoint",
                "setattr", "delattr", "getattr", "memoryview", "os", "sys", "subprocess", "socket", "shutil", "pathlib",
                "importlib", "pickle", "marshal", "ctypes", "httpx", "requests", "urllib", "anthropic"}
TEST_IMPORTS = {"__future__", "pytest", "datetime", "warden.detect", "warden.events", "warden.ingest", "warden.models"}


def check_code(code: str, allowed: set[str], kind: str) -> list[str]:
    problems = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"{kind}: syntax error line {e.lineno}: {e.msg}"]
    # getattr(obj, "plain_name") is ordinary defensive code; getattr with a computed or
    # underscore name is how sandbox escapes start. Allow only the first.
    safe_getattr = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            name = node.args[1] if len(node.args) > 1 else None
            if isinstance(name, ast.Constant) and isinstance(name.value, str) and not name.value.startswith("_"):
                safe_getattr.add(id(node.func))
            else:
                problems.append(f"{kind}: getattr needs a literal, non-underscore attribute name")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and id(node) in safe_getattr:
            continue
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in {x.split(".")[0] for x in allowed if not x.startswith(".")}:
                    problems.append(f"{kind}: import {a.name} not allowed")
        elif isinstance(node, ast.ImportFrom):
            mod = "." * node.level + (node.module or "")
            if mod not in allowed:
                problems.append(f"{kind}: from {mod} import ... not allowed")
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            problems.append(f"{kind}: use of {node.id} not allowed")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr not in ("__init__",):
            problems.append(f"{kind}: dunder attribute {node.attr} not allowed")
    return problems


def check_detection(code: str, rule_id: str) -> list[str]:
    problems = check_code(code, ALLOWED_IMPORTS, "detection")
    if problems:
        return problems
    tree = ast.parse(code)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    if len(classes) != 1:
        return [f"detection: expected exactly one class, found {len(classes)}"]
    c = classes[0]
    if not any(isinstance(d, ast.Name) and d.id == "register" for d in c.decorator_list):
        problems.append("detection: class is not decorated with @register")
    if not any(isinstance(b, ast.Name) and b.id == "Detection" for b in c.bases):
        problems.append("detection: class does not subclass Detection")
    attrs = {t.id: n.value for n in c.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    for a in ("id", "name", "mitre", "event_kinds", "playbook"):
        if a not in attrs:
            problems.append(f"detection: missing class attribute {a}")
    if "id" in attrs and not (isinstance(attrs["id"], ast.Constant) and attrs["id"].value == rule_id):
        problems.append(f"detection: id must be the literal {rule_id!r}")
    if not any(isinstance(n, ast.FunctionDef) and n.name == "run" for n in c.body):
        problems.append("detection: no run() method")
    from .detections import REGISTRY, load_all
    load_all()
    if rule_id in REGISTRY:
        problems.append(f"detection: id {rule_id} already exists")
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,48}", rule_id):
        problems.append("detection: id must be snake_case")
    return problems


# ---------------------------------------------------------------- persistence
def _row(pid: str, engine=None) -> dict | None:
    eng = engine or db.engine()
    with eng.connect() as c:
        r = c.execute(select(db.proposals).where(db.proposals.c.id == pid)).first()
    return dict(r._mapping) if r else None


def list_proposals(engine=None) -> list[dict]:
    eng = engine or db.engine()
    with eng.connect() as c:
        return [dict(r._mapping) for r in c.execute(select(db.proposals).order_by(db.proposals.c.created.desc()))]


def get(pid: str, engine=None) -> dict | None:
    return _row(pid, engine)


def _save(pid: str, engine=None, **vals) -> None:
    eng = engine or db.engine()
    with eng.begin() as c:
        if _row(pid, eng):
            c.execute(update(db.proposals).where(db.proposals.c.id == pid).values(updated=db.now(), **vals))
        else:
            c.execute(insert(db.proposals).values(id=pid, created=db.now(), updated=db.now(), **vals))


# ---------------------------------------------------------------- generation
def _interface_text() -> tuple[str, str, str]:
    reg = (ROOT / "warden" / "detections" / "__init__.py").read_text()
    iface = reg[: reg.index("def register(")]
    events = (ROOT / "warden" / "events.py").read_text()
    example = (ROOT / "warden" / "detections" / "account_create_then_privilege.py").read_text()
    return iface, events, example


def build_prompt(trigger: str, evidence: list[dict], context_docs: list[dict]) -> tuple[str, str]:
    from .detections import REGISTRY, load_all
    from .prompts import load
    load_all()
    p = load("propose")
    iface, events, example = _interface_text()
    ctx = "\n\n".join(f"[{d['id']}]\n{d['text']}" for d in context_docs) or "(none)"
    user = p.user.format(trigger=trigger, evidence=json.dumps(evidence[:120], indent=1, default=str),
                         interface=iface, event_model=events, example=example,
                         existing=", ".join(sorted(REGISTRY)), context=ctx)
    return p.system, user


class AnthropicProposer:
    def __init__(self, model: str | None = None):
        import anthropic
        headers = {"anthropic-workspace-id": settings.anthropic_workspace_id} if settings.anthropic_workspace_id else None
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key or None, default_headers=headers, max_retries=3)
        self.model = model or settings.proposal_model
        self.last_usage: dict = {}

    def propose(self, system: str, user: str) -> ProposalDraft:
        from .llm import cost_usd
        with self.client.beta.messages.stream(
            model=self.model, max_tokens=64000, system=system, messages=[{"role": "user", "content": user}],
            output_format=ProposalDraft, output_config={"effort": "high"}, thinking={"type": "adaptive"},
            betas=["server-side-fallback-2026-07-01"], fallbacks="default",
        ) as stream:
            resp = stream.get_final_message()
        u = resp.usage
        self.last_usage = {"model": resp.model, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
                           "cost_usd": cost_usd(resp.model, u.input_tokens, u.output_tokens)}
        if resp.stop_reason == "refusal" or resp.parsed_output is None:
            raise RuntimeError(f"no proposal (stop_reason={resp.stop_reason})")
        return resp.parsed_output


def create(trigger: str, events: list, context_query: str = "", techniques: list[str] | None = None,
           proposer=None, store=None, source: str = "") -> str:
    """Generate, check, evaluate, and queue a proposal. Returns its id."""
    from .knowledge import KnowledgeBase
    from .prompts import load
    anon = Anonymizer()
    evidence = [anon.event(e) for e in sorted(events, key=lambda e: e.ts)]
    kb = KnowledgeBase()
    docs = []
    if techniques:
        docs += kb.retrieve_by_technique(context_query or " ".join(techniques), techniques, k=4, kind="attack")
    if context_query:
        docs += kb.retrieve(context_query, 3, where={"kind": {"$in": ["playbook", "mitre", "policy"]}})
    system, user = build_prompt(trigger, evidence, docs)
    proposer = proposer or AnthropicProposer()
    pid = "PROP-" + hashlib.sha1(f"{trigger}|{source}|{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:8].upper()
    eng = store.engine if store else None
    draft = proposer.propose(system, user)
    gaps_found = incomplete(draft)
    if gaps_found:      # one retry, telling the model exactly what came back empty
        draft = proposer.propose(system, user + "\n\nYour previous draft was incomplete: " + "; ".join(gaps_found)
                                 + ". Return every field complete. No placeholders.")
    files = materialize(draft)
    usage = getattr(proposer, "last_usage", {}) or {}
    _save(pid, eng, trigger=trigger, source=source, status="generated", rule_id=draft.detection_id, evidence=evidence,
          rationale=draft.rationale, files=files, model=usage.get("model", getattr(proposer, "model", "")),
          prompt_version=load("propose").tag, cost_usd=usage.get("cost_usd"))
    problems = check_detection(draft.detection_code, draft.detection_id) + \
        check_code(draft.test_code, TEST_IMPORTS, "test")
    if problems:
        _save(pid, eng, status="rejected_static", checks={"static": problems})
        return pid
    results = sandbox_eval(files, draft.detection_id, evidence)
    ok = results.get("test", {}).get("ok") and results.get("positive_fires") and results.get("fires_on_evidence", True)
    _save(pid, eng, status="ready_for_review" if ok else "failed_eval", checks={"static": []}, eval=results,
          evidence=evidence)
    return pid


def incomplete(d: ProposalDraft) -> list[str]:
    out = []
    if len(d.test_code.strip()) < 80 or "placeholder" in d.test_code.lower()[:200]:
        out.append("test_code is empty or a placeholder")
    if not any(e.get("kind") and e.get("ts") for e in d.fixture.events):
        out.append("fixture.events_jsonl has no complete events")
    if "placeholder" in d.fixture.description.lower():
        out.append("fixture.description is a placeholder")
    if len(d.detection_code.strip()) < 200:
        out.append("detection_code is empty")
    return out


def materialize(d: ProposalDraft) -> dict[str, str]:
    slug = d.detection_id.replace("_", "-")
    fx = d.fixture
    expected = {"name": f"proposed: {d.detection_id}", "description": fx.description,
                "alerts": [{"rule": e.rule, "label": e.label,
                            "match": {k: v for k, v in (("user", e.match_user), ("host", e.match_host)) if v}}
                           for e in fx.expected_alerts]}
    return {
        f"warden/detections/{d.detection_id}.py": d.detection_code,
        f"data/knowledge/playbook-{slug}.md": d.playbook_markdown,
        f"data/eval/proposed-{slug}/events.jsonl": "\n".join(json.dumps(e) for e in fx.events) + "\n",
        f"data/eval/proposed-{slug}/expected.json": json.dumps(expected, indent=2) + "\n",
        f"tests/test_proposed_{d.detection_id}.py": d.test_code,
    }


# ---------------------------------------------------------------- sandbox evaluation
SANDBOX_SCRIPT = r'''
import json, sys
from pathlib import Path
from warden.detect import detect
from warden import evaluate
from warden.ingest import load_file
rule = sys.argv[1]
out = {}
for name, root in (("synthetic", "data/eval"), ("real", "data/eval-real")):
    cases = evaluate.discover(Path(root), skip_missing=True)
    rep = evaluate.run(cases, with_llm=False)
    out[name] = {"overall": rep.to_dict()["overall"], "rule": rep.to_dict()["per_rule"].get(rule),
                 "spurious": [s for s in rep.spurious if f": {rule} " in s]}
# replay the new rule alone over every event we have and count what it fires on
hits = []
paths = [p for p in Path("data/eval").glob("*/events.jsonl") if "proposed-" not in str(p)]
paths += sorted(Path("data/real").glob("*.evtx"))
for p in paths:
    try:
        for a in detect(load_file(p), only=[rule]):
            hits.append({"file": str(p), "title": a.title})
    except Exception as e:
        hits.append({"file": str(p), "error": str(e)[:200]})
out["historical_hits"] = hits
if len(sys.argv) > 2 and sys.argv[2]:
    out["fires_on_evidence"] = bool(detect(load_file(Path(sys.argv[2]), fmt="generic"), only=[rule]))
print("WARDEN_SANDBOX_RESULT " + json.dumps(out))
'''


def sandbox_eval(files: dict[str, str], rule_id: str, evidence: list[dict] | None = None, timeout: int = 300) -> dict:
    """Copy the repo to a temp dir, add the proposal, and run its test, both eval suites,
    and a replay of the new rule over every event on disk, in a subprocess with no secrets
    in its environment. The static checks already refused I/O, network, and dynamic code;
    the subprocess and timeout contain what they cannot see."""
    tmp = Path(tempfile.mkdtemp(prefix="warden-proposal-"))
    try:
        ignore = shutil.ignore_patterns(".git", ".venv", "__pycache__", "chroma", "state", "attack", ".pytest_cache", "soak")
        shutil.copytree(ROOT, tmp / "repo", ignore=ignore, symlinks=True)
        repo = tmp / "repo"
        for rel, content in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(content)
        if evidence:
            (tmp / "evidence.jsonl").write_text("\n".join(json.dumps(e) for e in evidence) + "\n")
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp), "WARDEN_LLM": "mock", "WARDEN_EMBEDDINGS": "hash",
               "WARDEN_DATA_DIR": str(repo / "data"), "PYTHONPATH": str(repo), "PYTHONDONTWRITEBYTECODE": "1"}
        out: dict = {}
        test = [p for p in files if p.startswith("tests/")][0]
        t = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test], cwd=repo, env=env,
                           capture_output=True, text=True, timeout=timeout)
        out["test"] = {"ok": t.returncode == 0, "output": (t.stdout + t.stderr)[-2500:]}
        e = subprocess.run([sys.executable, "-c", SANDBOX_SCRIPT, rule_id, str(tmp / "evidence.jsonl") if evidence else ""],
                           cwd=repo, env=env, capture_output=True,
                           text=True, timeout=timeout)
        line = next((ln for ln in e.stdout.splitlines() if ln.startswith("WARDEN_SANDBOX_RESULT ")), None)
        if line:
            out.update(json.loads(line.split(" ", 1)[1]))
        else:
            out["eval_error"] = (e.stdout + e.stderr)[-2500:]
        slug = rule_id.replace("_", "-")
        own = [h for h in out.get("historical_hits", []) if f"proposed-{slug}" in h.get("file", "")]
        out["positive_fires"] = bool(out.get("synthetic", {}).get("rule", {}) and
                                     out["synthetic"]["rule"].get("tp", 0) > 0) or bool(own)
        return out
    except subprocess.TimeoutExpired:
        return {"error": f"sandbox timed out after {timeout}s"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- triggers
def gaps(limit: int = 20) -> list[dict]:
    """ATT&CK techniques with detection guidance and no rule mapped to them (or their parent)."""
    from .attack import parse, fetch_bundle
    from .detections import REGISTRY, load_all
    load_all()
    covered = {t for d in REGISTRY.values() for t in d.mitre}
    covered_base = {t.split(".")[0] for t in covered}
    mf = settings.attack_dir
    techniques = []
    for f in sorted(mf.glob("T*.md")):
        tid = f.stem
        text = f.read_text()
        if tid in covered or (tid.split(".")[0] in covered_base and "." not in tid):
            continue
        if "## Detection guidance" not in text:
            continue
        tactics = next((ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("Tactics:")), "")
        groups = next((ln for ln in text.split("## Associated groups")[1:2]), "")
        techniques.append({"technique": tid, "title": text.splitlines()[0][2:], "tactics": tactics,
                           "groups": len(groups.split(",")) if groups else 0})
    from .tdl import coverage
    tdl_rules = {g["technique"]: g["tdl_rules"] for g in coverage().get("gaps", [])}
    for t in techniques:      # a gap TDL already writes rules for is better evidenced than one it doesn't
        t["tdl_rules"] = tdl_rules.get(t["technique"], 0)
    return sorted(techniques, key=lambda t: (-t["tdl_rules"], -t["groups"]))[:limit]


def should_propose(case) -> bool:
    """TP on an anomaly-only case, or the analyst asked for a rule in the note."""
    if case.analyst_verdict != "true_positive":
        return False
    rules = case.alert.rules()
    wants = bool(re.search(r"(should be|needs|deserves)\s+(its own|a)\s+rule|propose a rule", case.analyst_note or "", re.I))
    return wants or all(r.startswith("anomaly.") for r in rules)


# ---------------------------------------------------------------- review and PR
def recheck(pid: str, store=None) -> str:
    """Re-run static checks and the sandbox on a stored proposal (after a checker or
    harness change) without asking the model again."""
    eng = store.engine if store else None
    p = _row(pid, eng)
    det = next(v for k, v in p["files"].items() if k.startswith("warden/detections/"))
    test = next(v for k, v in p["files"].items() if k.startswith("tests/"))
    problems = check_detection(det, p["rule_id"]) + check_code(test, TEST_IMPORTS, "test")
    if problems:
        _save(pid, eng, status="rejected_static", checks={"static": problems})
        return "rejected_static"
    results = sandbox_eval(p["files"], p["rule_id"], p.get("evidence"))
    ok = results.get("test", {}).get("ok") and results.get("positive_fires") and results.get("fires_on_evidence", True)
    status = "ready_for_review" if ok else "failed_eval"
    _save(pid, eng, status=status, checks={"static": []}, eval=results)
    return status


def review(pid: str, decision: str, actor: str, note: str = "", store=None, open_pr: bool = True) -> dict:
    """approve -> commit the files on a new branch in a separate worktree and open a PR.
    reject -> record why. Either way the decision lands in the audit log."""
    eng = store.engine if store else None
    p = _row(pid, eng)
    if not p:
        raise KeyError(pid)
    if decision == "reject":
        _save(pid, eng, status="rejected", review={"by": actor, "note": note})
        if store:
            store.audit(actor, "reject_proposal", pid, note=note)
        return {"status": "rejected"}
    if p["status"] != "ready_for_review":
        raise ValueError(f"{pid} is {p['status']}, not ready_for_review")
    pr = open_pull_request(pid, p) if open_pr else None
    _save(pid, eng, status="pr_opened" if pr else "approved", review={"by": actor, "note": note}, pr_url=pr)
    if store:
        store.audit(actor, "approve_proposal", pid, pr=pr, rule=p["rule_id"])
    return {"status": "pr_opened" if pr else "approved", "pr": pr}


def open_pull_request(pid: str, p: dict) -> str:
    branch = f"proposal/{p['rule_id'].replace('_', '-')}-{pid[-4:].lower()}"
    wt = Path(tempfile.mkdtemp(prefix="warden-pr-"))
    run = lambda *a, **k: subprocess.run(a, cwd=k.pop("cwd", ROOT), check=True, capture_output=True, text=True, **k)  # noqa: E731
    run("git", "fetch", "-q", "origin", "main")
    run("git", "worktree", "add", "-q", "-b", branch, str(wt), "origin/main")
    try:
        for rel, content in p["files"].items():
            (wt / rel).parent.mkdir(parents=True, exist_ok=True)
            (wt / rel).write_text(content)
        run("git", "add", "-A", cwd=wt)
        ev = p.get("eval") or {}
        msg = (f"Proposed detection: {p['rule_id']}\n\n{p['rationale']}\n\nGenerated by {p['model']} "
               f"({p['prompt_version']}) from {p['trigger']} {p['source']}; reviewed in Warden as {pid}.\n\n"
               "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>")
        run("git", "commit", "-q", "-m", msg, cwd=wt)
        run("git", "push", "-q", "-u", "origin", branch, cwd=wt)
        syn, real = ev.get("synthetic", {}), ev.get("real", {})
        body = (f"## {p['rule_id']}\n\n{p['rationale']}\n\n"
                f"**Trigger:** {p['trigger']} `{p['source']}`  \n**Model:** {p['model']} · prompt `{p['prompt_version']}`\n\n"
                f"### Sandbox evaluation\n| Suite | Precision | Recall | New rule TP/FP/FN |\n|---|---|---|---|\n"
                f"| synthetic | {syn.get('overall', {}).get('precision')} | {syn.get('overall', {}).get('recall')} | {syn.get('rule')} |\n"
                f"| real | {real.get('overall', {}).get('precision')} | {real.get('overall', {}).get('recall')} | {real.get('rule')} |\n\n"
                f"Proposed test: {'passed' if ev.get('test', {}).get('ok') else 'FAILED'}. "
                f"Fires on {len(ev.get('historical_hits', []))} historical file(s).\n\n"
                "Generated as a proposal; nothing is loaded until this merges.\n\n"
                "🤖 Generated with [Claude Code](https://claude.com/claude-code)")
        r = run("gh", "pr", "create", "--base", "main", "--head", branch, "--title", f"Proposed detection: {p['rule_id']}",
                "--body", body, cwd=wt)
        return r.stdout.strip().splitlines()[-1]
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=ROOT, capture_output=True)
