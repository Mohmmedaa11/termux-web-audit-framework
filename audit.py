#!/usr/bin/env python3
"""Low-impact, allowlist-based web audit runner for authorized testing."""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

USER_AGENT = "Termux-Web-Audit/1.0 (authorized-security-testing)"
TOOLS = {"nmap", "nikto", "nuclei", "whatweb", "wafw00f"}
SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    evidence: str
    remediation: str
    source: str = "core"


def load_scope(path: str) -> list[str]:
    values = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip().lower().rstrip(".")
        if line and not line.startswith("#"):
            values.append(line.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0])
    return sorted(set(values))


def in_scope(target: str, scope: list[str]) -> bool:
    host = (urlparse(target).hostname or "").lower().rstrip(".")
    return bool(host) and any(host == item or host.endswith("." + item) for item in scope)


def normalize_target(raw: str) -> str:
    value = raw if "://" in raw else "https://" + raw
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an http(s) URL")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def request(target: str, method: str = "GET", timeout: int = 10):
    req = Request(target, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(65536)
            return response.status, dict(response.headers.items()), body, None
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read(65536), None
    except (URLError, TimeoutError, OSError) as exc:
        return None, {}, b"", str(exc)


def check_headers(target: str) -> list[Finding]:
    status, headers, body, error = request(target)
    if error:
        return [Finding("CORE-001", "تعذر الوصول إلى الهدف", "Info", "High", error, "تحقق من DNS والاتصال والتصريح.")]
    lowered = {k.lower(): v for k, v in headers.items()}
    findings = []
    checks = [
        ("strict-transport-security", "CORE-HTTPS-001", "غياب HSTS", "Low", "أضف Strict-Transport-Security بعد التأكد من جاهزية HTTPS.", "تحسين دفاعي؛ لا يثبت وجود ثغرة."),
        ("content-security-policy", "CORE-HEAD-001", "غياب Content-Security-Policy", "Medium", "صمّم CSP تدريجيًا وراقب التقارير قبل فرضها.", "قد يزيد أثر XSS عند وجود نقاط حقن أخرى."),
        ("x-content-type-options", "CORE-HEAD-002", "غياب X-Content-Type-Options", "Low", "اضبط X-Content-Type-Options: nosniff.", "يقلل MIME sniffing."),
        ("referrer-policy", "CORE-HEAD-003", "غياب Referrer-Policy", "Low", "اضبط سياسة إحالة مناسبة مثل strict-origin-when-cross-origin.", "يقلل تسرب عناوين URL."),
        ("permissions-policy", "CORE-HEAD-004", "غياب Permissions-Policy", "Low", "قيّد ميزات المتصفح غير اللازمة.", "تحسين دفاعي."),
    ]
    for header, fid, title, sev, fix, evidence in checks:
        if header not in lowered:
            findings.append(Finding(fid, title, sev, "Medium", evidence, fix))
    server = lowered.get("server")
    if server:
        findings.append(Finding("CORE-INFO-001", "كشف ترويسة Server", "Info", "High", server, "قلّل تفاصيل الإصدار المكشوفة إن لم تكن لازمة."))
    if target.startswith("https://") and "strict-transport-security" not in lowered:
        pass
    if status and status >= 500:
        findings.append(Finding("CORE-HTTP-001", "استجابة خادم 5xx", "Medium", "Medium", f"HTTP {status}", "راجع السجلات ومعالجة الأخطاء؛ تحقق من عدم تسريب تفاصيل داخل الاستجابة."))
    return findings


def check_common_files(target: str) -> list[Finding]:
    results = []
    base = target.rstrip("/")
    for path, fid, title in [("/robots.txt", "CORE-DISC-001", "وجود robots.txt"), ("/.well-known/security.txt", "CORE-DISC-002", "وجود security.txt")]:
        status, headers, body, error = request(base + path, timeout=8)
        if status and 200 <= status < 300 and body:
            results.append(Finding(fid, title, "Info", "High", f"HTTP {status}, {len(body)} bytes", "راجع المحتوى يدويًا وتأكد من عدم كشف أسرار أو مسارات حساسة.", "core"))
    return results


def run_tool(tool: str, target: str, raw_dir: Path, timeout: int) -> list[Finding]:
    if tool not in TOOLS or not shutil.which(tool):
        return [Finding("TOOL-001", f"الأداة غير متاحة: {tool}", "Info", "High", "لم يتم العثور عليها في PATH.", "ثبّت الأداة من مصدرها الرسمي أو تجاهلها.", tool)]
    # Intentionally fixed, non-exploitative argument sets. Do not add user-supplied flags.
    commands = {
        "nmap": [tool, "-Pn", "-T2", "--top-ports", "20", "-sV", "--version-light", urlparse(target).hostname or ""],
        "nikto": [tool, "-nointeractive", "-maxtime", "60s", "-host", target],
        "nuclei": [tool, "-u", target, "-severity", "info,low,medium,high", "-rl", "2", "-c", "1", "-silent"],
        "whatweb": [tool, "--no-errors", "--log-brief=-", target],
        "wafw00f": [tool, "-a", target],
    }
    cmd = commands[tool]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        output = (proc.stdout + "\n" + proc.stderr).strip()
        (raw_dir / f"{tool}.txt").write_text(output + "\n", encoding="utf-8")
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else "timeout"
        (raw_dir / f"{tool}.txt").write_text(output + "\n[TIMEOUT]\n", encoding="utf-8")
        return [Finding(f"TOOL-{tool}", f"انتهت مهلة {tool}", "Info", "High", "تم إيقاف الأداة بعد المهلة.", "راجع المعدل والمهلة وبيئة الاختبار.", tool)]
    sev = "Info"
    if re.search(r"critical|remote code execution|rce", output, re.I): sev = "Critical"
    elif re.search(r"high|command injection|sql injection|xss", output, re.I): sev = "High"
    elif re.search(r"medium|moderate|missing security header", output, re.I): sev = "Medium"
    elif output: sev = "Low"
    evidence = " ".join(output.split())[:500] or f"exit={proc.returncode}"
    return [Finding(f"TOOL-{tool}", f"مخرجات {tool} تحتاج مراجعة", sev, "Low", evidence, "تحقق يدويًا من النتيجة قبل اعتبارها ثغرة، ثم أصلح السبب الجذري.", tool)]


def render_md(report: dict[str, Any]) -> str:
    lines = ["# تقرير فحص أمني مصرح به", "", f"- الهدف: `{report['target']}`", f"- الوقت: `{report['started_at']}`", f"- النطاق: `{report['scope_file']}`", f"- أعلى خطورة: **{report['summary']['max_severity']}**", "", "> هذا التقرير مؤشرات آلية وليس إثباتًا نهائيًا لثغرة. يلزم التحقق اليدوي ضمن التفويض.", "", "## النتائج", ""]
    if not report["findings"]: lines.append("لم تُسجل مؤشرات في الفحوصات المنفذة.")
    for f in sorted(report["findings"], key=lambda x: -SEVERITY_ORDER[x["severity"]]):
        lines += [f"### {f['severity']} — {f['title']}", f"- المعرّف: `{f['id']}` | المصدر: `{f['source']}` | الثقة: `{f['confidence']}`", f"- الدليل: {f['evidence']}", f"- المعالجة: {f['remediation']}", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Allowlist-based low-impact web auditor")
    sub = parser.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="run an authorized audit")
    scan.add_argument("--target", required=True)
    scan.add_argument("--scope", default="config/scope.txt")
    scan.add_argument("--out", default="reports")
    scan.add_argument("--tool", action="append", choices=sorted(TOOLS), default=[])
    scan.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    if args.action == "scan":
        target = normalize_target(args.target)
        scope = load_scope(args.scope)
        if not in_scope(target, scope):
            print("رفض: الهدف خارج قائمة السماح.", file=sys.stderr); return 2
        started = datetime.now(timezone.utc).isoformat()
        out = Path(args.out); raw = out / "raw"; raw.mkdir(parents=True, exist_ok=True)
        findings = check_headers(target) + check_common_files(target)
        for tool in args.tool: findings.extend(run_tool(tool, target, raw, args.timeout))
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        max_sev = max((f.severity for f in findings), key=lambda x: SEVERITY_ORDER[x], default="Info")
        report = {"target": target, "scope_file": args.scope, "started_at": started, "findings": [asdict(f) for f in findings], "summary": {"counts": counts, "max_severity": max_sev, "tools": args.tool}}
        (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out / "report.md").write_text(render_md(report), encoding="utf-8")
        print(json.dumps(report["summary"], ensure_ascii=False))
        return 0
    return 1

if __name__ == "__main__": raise SystemExit(main())
