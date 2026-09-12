#!/usr/bin/env python3
"""Allowlist-based, low-impact web audit runner for authorized testing only."""
from __future__ import annotations
import argparse, csv, json, re, shutil, socket, ssl, subprocess, sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

USER_AGENT = "Termux-Web-Audit/3.0 (authorized-security-testing)"
SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEVERITY_SCORE = {"Info": 0, "Low": 2, "Medium": 5, "High": 8, "Critical": 10}

TOOL_PROFILES = {
    "nmap": lambda t: ["nmap", "-Pn", "-T2", "--top-ports", "20", "-sV", "--version-light", urlparse(t).hostname or ""],
    "nikto": lambda t: ["nikto", "-nointeractive", "-maxtime", "60s", "-host", t],
    "nuclei": lambda t: ["nuclei", "-u", t, "-severity", "info,low,medium,high", "-rl", "2", "-c", "1", "-silent"],
    "whatweb": lambda t: ["whatweb", "--no-errors", "--log-brief=-", t],
    "wafw00f": lambda t: ["wafw00f", "-a", t],
    "httpx": lambda t: ["httpx", "-u", t, "-status-code", "-title", "-tech-detect", "-follow-redirects", "-silent"],
    "dnsx": lambda t: ["dnsx", "-d", urlparse(t).hostname or "", "-a", "-aaaa", "-cname", "-resp", "-silent"],
    "subfinder": lambda t: ["subfinder", "-d", urlparse(t).hostname or "", "-silent", "-timeout", "10"],
    "assetfinder": lambda t: ["assetfinder", "--subs-only", urlparse(t).hostname or ""],
    "amass": lambda t: ["amass", "enum", "-passive", "-d", urlparse(t).hostname or ""],
    "dig": lambda t: ["dig", "+time=3", "+tries=1", urlparse(t).hostname or "", "A", "AAAA", "MX", "TXT"],
    "host": lambda t: ["host", urlparse(t).hostname or ""],
    "curl": lambda t: ["curl", "-sSIL", "--max-time", "10", "-A", USER_AGENT, t],
    "openssl": lambda t: ["openssl", "s_client", "-connect", f"{urlparse(t).hostname}:443", "-servername", urlparse(t).hostname or "", "-brief"],
    "sslscan": lambda t: ["sslscan", "--no-colour", "--timeout=5", f"{urlparse(t).hostname}:443"],
    "testssl": lambda t: ["testssl", "--quiet", "--warnings", "batch", t],
    "searchsploit": lambda t: ["searchsploit", "--json", urlparse(t).hostname or ""],
    "zap-baseline": lambda t: ["zap-baseline.py", "-t", t, "-m", "1", "-I", "-T", "60"],
}
TOOLS = set(TOOL_PROFILES)

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


def load_targets(path: str) -> list[str]:
    values = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            values.append(line)
    return values


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
            return response.status, dict(response.headers.items()), response.read(65536), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read(65536), None
    except (URLError, TimeoutError, OSError) as exc:
        return None, {}, b"", str(exc)


def check_headers(target: str) -> list[Finding]:
    status, headers, _, error = request(target)
    if error:
        return [Finding("CORE-001", "تعذر الوصول إلى الهدف", "Info", "High", error, "تحقق من DNS والاتصال والتصريح.")]
    lowered = {k.lower(): v for k, v in headers.items()}
    findings = []
    checks = [
        ("strict-transport-security", "CORE-HTTPS-001", "غياب HSTS", "Low", "أضف Strict-Transport-Security بعد التأكد من جاهزية HTTPS.", "تحسين دفاعي؛ لا يثبت وجود ثغرة."),
        ("content-security-policy", "CORE-HEAD-001", "غياب Content-Security-Policy", "Medium", "صمّم CSP تدريجيًا وراقب التقارير قبل فرضها.", "قد يزيد أثر XSS عند وجود نقاط حقن أخرى."),
        ("x-content-type-options", "CORE-HEAD-002", "غياب X-Content-Type-Options", "Low", "اضبط X-Content-Type-Options: nosniff.", "يقلل MIME sniffing."),
        ("referrer-policy", "CORE-HEAD-003", "غياب Referrer-Policy", "Low", "اضبط سياسة إحالة مناسبة.", "يقلل تسرب عناوين URL."),
        ("permissions-policy", "CORE-HEAD-004", "غياب Permissions-Policy", "Low", "قيّد ميزات المتصفح غير اللازمة.", "تحسين دفاعي."),
    ]
    for header, fid, title, sev, fix, evidence in checks:
        if header not in lowered:
            findings.append(Finding(fid, title, sev, "Medium", evidence, fix))
    if lowered.get("server"):
        findings.append(Finding("CORE-INFO-001", "كشف ترويسة Server", "Info", "High", lowered["server"], "قلّل تفاصيل الإصدار المكشوفة إن لم تكن لازمة."))
    if lowered.get("access-control-allow-origin") == "*":
        findings.append(Finding("CORE-CORS-001", "CORS يسمح لجميع المصادر", "Medium", "High", "Access-Control-Allow-Origin: *", "قيّد المصادر المسموح بها ولا تستخدم * مع بيانات حساسة أو credentials."))
    set_cookie = lowered.get("set-cookie", "").lower()
    if set_cookie:
        if "secure" not in set_cookie and target.startswith("https://"):
            findings.append(Finding("CORE-COOKIE-001", "Cookie دون Secure", "Medium", "Medium", "Set-Cookie لا يحتوي Secure", "أضف Secure إلى الكوكيز التي تُرسل عبر HTTPS."))
        if "httponly" not in set_cookie:
            findings.append(Finding("CORE-COOKIE-002", "Cookie دون HttpOnly", "Low", "Medium", "Set-Cookie لا يحتوي HttpOnly", "أضف HttpOnly إلى كوكيز الجلسة غير المطلوبة من JavaScript."))
        if "samesite" not in set_cookie:
            findings.append(Finding("CORE-COOKIE-003", "Cookie دون SameSite", "Low", "Medium", "Set-Cookie لا يحتوي SameSite", "حدد SameSite=Lax أو Strict حسب تدفق التطبيق."))
    if status and status >= 500:
        findings.append(Finding("CORE-HTTP-001", "استجابة خادم 5xx", "Medium", "Medium", f"HTTP {status}", "راجع السجلات ومعالجة الأخطاء وتحقق من عدم تسريب تفاصيل."))
    return findings


def check_dns_tls(target: str) -> list[Finding]:
    host = urlparse(target).hostname or ""
    findings = []
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        if addresses:
            findings.append(Finding("CORE-DNS-INFO", "عناوين DNS المكتشفة", "Info", "High", ", ".join(addresses[:10]), "راجع أن العناوين ضمن الأصول المصرح بها."))
    except socket.gaierror as exc:
        findings.append(Finding("CORE-DNS-001", "فشل حل DNS", "Medium", "High", str(exc), "تحقق من سجلات DNS والاتصال."))
    if urlparse(target).scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    findings.append(Finding("CORE-TLS-INFO", "معلومات TLS", "Info", "High", f"version={tls.version()} cipher={cipher[0] if cipher else 'unknown'}", "حافظ على إصدارات ومجموعات تشفير مدعومة.", "tls"))
                    expiry = cert.get("notAfter")
                    if expiry:
                        expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (expiry_dt - datetime.now(timezone.utc)).days
                        if days < 0:
                            findings.append(Finding("CORE-TLS-001", "شهادة TLS منتهية", "High", "High", f"انتهت منذ {-days} يومًا", "جدد الشهادة فورًا." , "tls"))
                        elif days < 30:
                            findings.append(Finding("CORE-TLS-002", "شهادة TLS قاربت الانتهاء", "Medium", "High", f"متبقٍ {days} يومًا", "جدد الشهادة قبل انتهاء الصلاحية.", "tls"))
        except (OSError, ssl.SSLError, ValueError) as exc:
            findings.append(Finding("CORE-TLS-003", "تعذر التحقق من TLS", "Medium", "Medium", str(exc), "تحقق من الشهادة وسلسلة الثقة وإتاحة المنفذ 443.", "tls"))
    return findings


def check_common_files(target: str) -> list[Finding]:
    results = []
    base = target.rstrip("/")
    for path, fid, title in [("/robots.txt", "CORE-DISC-001", "وجود robots.txt"), ("/.well-known/security.txt", "CORE-DISC-002", "وجود security.txt")]:
        status, _, body, _ = request(base + path, timeout=8)
        if status and 200 <= status < 300 and body:
            results.append(Finding(fid, title, "Info", "High", f"HTTP {status}, {len(body)} bytes", "راجع المحتوى يدويًا وتأكد من عدم كشف أسرار أو مسارات حساسة."))
    return results


def severity_for_output(output: str) -> str:
    if re.search(r"critical|remote code execution|\brce\b", output, re.I): return "Critical"
    if re.search(r"high|command injection|sql injection|\bxss\b", output, re.I): return "High"
    if re.search(r"medium|moderate|missing security header", output, re.I): return "Medium"
    return "Low" if output.strip() else "Info"


def run_tool(tool: str, target: str, raw_dir: Path, timeout: int, dry_run: bool = False) -> list[Finding]:
    command = TOOL_PROFILES[tool](target)
    if dry_run:
        return [Finding(f"DRYRUN-{tool}", f"معاينة أمر {tool}", "Info", "High", " ".join(command), "أزل --dry-run فقط بعد مراجعة النطاق والتفويض.", tool)]
    if not shutil.which(command[0]):
        return [Finding(f"TOOL-MISSING-{tool}", f"الأداة غير مثبتة: {tool}", "Info", "High", "لم يتم العثور عليها في PATH.", "ثبّت الأداة من مصدرها الرسمي أو تجاهلها.", tool)]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        output = (proc.stdout + "\n" + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        output, proc = "[TIMEOUT]", None
    (raw_dir / f"{tool}.txt").write_text(output + "\n", encoding="utf-8")
    if output == "[TIMEOUT]":
        return [Finding(f"TOOL-TIMEOUT-{tool}", f"انتهت مهلة {tool}", "Info", "High", "تم إيقاف الأداة بعد المهلة.", "راجع المعدل والمهلة وبيئة الاختبار.", tool)]
    evidence = " ".join(output.split())[:600] or f"exit={proc.returncode}"
    return [Finding(f"TOOL-{tool}", f"مخرجات {tool} تحتاج مراجعة", severity_for_output(output), "Low", evidence, "تحقق يدويًا من النتيجة قبل اعتبارها ثغرة، ثم أصلح السبب الجذري.", tool)]


def summarize(findings: list[Finding], tools: list[str]) -> dict[str, Any]:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    max_sev = max((f.severity for f in findings), key=lambda x: SEVERITY_ORDER[x], default="Info")
    score = min(100, sum(SEVERITY_SCORE[f.severity] for f in findings))
    return {"counts": counts, "max_severity": max_sev, "risk_score": score, "tools": tools}


def render_md(report: dict[str, Any]) -> str:
    lines = ["# تقرير فحص أمني مصرح به", "", f"- الأهداف: **{len(report['targets'])}**", f"- الوقت: `{report['started_at']}`", f"- أعلى خطورة: **{report['summary']['max_severity']}**", f"- مجموع نقاط المخاطر: **{report['summary']['risk_score']}/100**", "", "> هذا التقرير مؤشرات آلية وليس إثباتًا نهائيًا لثغرة. يلزم التحقق اليدوي ضمن التفويض.", ""]
    for target in report["targets"]:
        lines += [f"## {target}", ""]
        findings = [f for f in report["findings"] if f["target"] == target]
        if not findings: lines.append("لم تُسجل مؤشرات.")
        for f in sorted(findings, key=lambda x: -SEVERITY_ORDER[x["severity"]]):
            lines += [f"### {f['severity']} — {f['title']}", f"- `{f['id']}` | المصدر: `{f['source']}` | الثقة: `{f['confidence']}`", f"- الدليل: {f['evidence']}", f"- المعالجة: {f['remediation']}", ""]
    return "\n".join(lines)


def write_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    fields = ["target", "id", "title", "severity", "confidence", "source", "evidence", "remediation"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader()
        writer.writerows({key: item.get(key, "") for key in fields} for item in findings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Allowlist-based low-impact web auditor")
    parser.add_argument("--list-tools", action="store_true")
    sub = parser.add_subparsers(dest="action")
    scan = sub.add_parser("scan", help="run an authorized audit")
    scan.add_argument("--target", action="append", help="target URL; repeat for multiple targets")
    scan.add_argument("--targets-file", help="file containing one target URL per line")
    scan.add_argument("--scope", default="config/scope.txt")
    scan.add_argument("--out", default="reports")
    scan.add_argument("--tool", action="append", choices=sorted(TOOLS), default=[])
    scan.add_argument("--all", action="store_true")
    scan.add_argument("--dry-run", action="store_true", help="show fixed commands without executing them")
    scan.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    if args.list_tools:
        print("\n".join(sorted(TOOLS))); return 0
    if args.action != "scan": parser.print_help(); return 1
    raw_targets = list(args.target or [])
    if args.targets_file: raw_targets.extend(load_targets(args.targets_file))
    if not raw_targets: print("يجب تحديد --target أو --targets-file", file=sys.stderr); return 2
    scope = load_scope(args.scope)
    targets = []
    for raw in raw_targets:
        target = normalize_target(raw)
        if not in_scope(target, scope): print(f"رفض: خارج النطاق: {target}", file=sys.stderr); return 2
        if target not in targets: targets.append(target)
    out = Path(args.out); raw_dir = out / "raw"; raw_dir.mkdir(parents=True, exist_ok=True)
    selected = sorted(TOOLS) if args.all else args.tool
    started = datetime.now(timezone.utc).isoformat(); all_findings = []
    for target in targets:
        findings = check_headers(target) + check_dns_tls(target) + check_common_files(target)
        target_raw_dir = raw_dir / (urlparse(target).hostname or "unknown-host")
        target_raw_dir.mkdir(parents=True, exist_ok=True)
        for tool in selected: findings.extend(run_tool(tool, target, target_raw_dir, args.timeout, args.dry_run))
        for finding in findings:
            item = asdict(finding); item["target"] = target; all_findings.append(item)
    summary = summarize([Finding(**{k: item[k] for k in Finding.__dataclass_fields__}) for item in all_findings], selected)
    report = {"targets": targets, "scope_file": args.scope, "started_at": started, "findings": all_findings, "summary": summary}
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_md(report), encoding="utf-8")
    write_csv(out / "report.csv", all_findings)
    print(json.dumps(summary, ensure_ascii=False)); return 0

if __name__ == "__main__": raise SystemExit(main())
