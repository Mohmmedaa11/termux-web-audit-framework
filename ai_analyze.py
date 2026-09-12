#!/usr/bin/env python3
"""Optional AI triage for an existing authorized audit report.

The model is an assistant: it must not invent evidence or claim exploitability.
No network call occurs unless this script is explicitly run.
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path

SYSTEM = """You are a senior application-security reviewer assisting an authorized assessment.
Analyze only the supplied automated findings. Never invent evidence, CVEs, exploit steps,
credentials, or affected endpoints. Treat every finding as a hypothesis requiring validation.
Prioritize by likely impact and confidence. Recommend safe manual verification and remediation.
Do not provide weaponized exploit payloads or instructions to bypass authentication.
Return JSON matching the schema exactly."""
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "executive_summary": {"type": "string"},
        "risk_posture": {"type": "string", "enum": ["critical", "high", "moderate", "low", "unknown"]},
        "prioritized_findings": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {
            "finding_id": {"type": "string"}, "priority": {"type": "integer", "minimum": 1, "maximum": 5},
            "assessment": {"type": "string"}, "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "safe_validation": {"type": "string"}, "remediation": {"type": "string"}
        }, "required": ["finding_id", "priority", "assessment", "confidence", "safe_validation", "remediation"]}},
        "manual_tests_to_run": {"type": "array", "items": {"type": "string"}},
        "false_positive_notes": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["executive_summary", "risk_posture", "prioritized_findings", "manual_tests_to_run", "false_positive_notes"]
}


def main() -> int:
    parser = argparse.ArgumentParser(description="AI triage for a local audit report")
    parser.add_argument("report", help="path to report.json")
    parser.add_argument("--out", default="ai-review.json")
    parser.add_argument("--model", default="gpt-5-mini")
    parser.add_argument("--include-raw", action="store_true", help="include raw tool excerpts if present")
    args = parser.parse_args()
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("OPENAI_API_BASE"):
        print("OPENAI_API_KEY و OPENAI_API_BASE مطلوبان لتشغيل تحليل AI.", file=sys.stderr); return 2
    try:
        from openai import OpenAI
    except ImportError:
        print("ثبّت الاعتمادية الاختيارية: pip install openai", file=sys.stderr); return 2
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    if not args.include_raw:
        report.pop("raw", None)
    prompt = "حلل التقرير التالي دون اختلاق معلومات. اربط كل استنتاج بمعرّف finding_id موجود:\n" + json.dumps(report, ensure_ascii=False)
    client = OpenAI()
    response = client.chat.completions.create(
        model=args.model,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        response_format={"type": "json_schema", "json_schema": {"name": "security_review", "strict": True, "schema": SCHEMA}},
        max_completion_tokens=4000,
    )
    content = response.choices[0].message.content
    if not content:
        print("لم يُرجع النموذج محتوى.", file=sys.stderr); return 1
    review = json.loads(content)
    Path(args.out).write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"تم حفظ مراجعة AI في {args.out}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
