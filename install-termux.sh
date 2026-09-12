#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

if [[ "${PREFIX:-}" != *com.termux* ]]; then
  echo "هذا المثبت مخصص لـ Termux فقط." >&2
  exit 1
fi

pkg update -y
pkg upgrade -y
pkg install -y python git curl dnsutils openssl nmap

chmod +x audit.py manual_plan.py

python audit.py --list-tools
python -m unittest discover -s tests -v

echo
echo "اكتمل التثبيت. مثال آمن:"
echo "  python audit.py interactive --out reports"
echo "  python audit.py scan --target https://staging.example.com --out reports --dry-run"
echo "راجع README.md قبل تشغيل أي أداة خارجية."
