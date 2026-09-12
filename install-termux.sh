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
if [[ ! -f config/scope.txt ]]; then
  cp config/scope.txt.example config/scope.txt
  echo "تم إنشاء config/scope.txt؛ عدّله وأضف النطاقات المصرح بها فقط."
fi

python audit.py --list-tools
python -m unittest discover -s tests -v

echo
echo "اكتمل التثبيت. مثال آمن:"
echo "  python audit.py scan --target https://staging.example.com --scope config/scope.txt --out reports --dry-run"
echo "راجع README.md قبل تشغيل أي أداة خارجية."
