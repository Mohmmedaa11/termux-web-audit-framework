#!/data/data/com.termux/files/usr/bin/bash
set -u

if [[ "${PREFIX:-}" != *com.termux* ]]; then
  echo "هذا المثبت مخصص لـ Termux فقط." >&2
  exit 1
fi

export PATH="$HOME/go/bin:$PREFIX/bin:$PATH"
mkdir -p "$HOME/go/bin" "$HOME/tools"

ok=(); fail=()
run_step() {
  local name="$1"; shift
  echo
  echo "[+] تثبيت $name"
  if "$@"; then ok+=("$name"); echo "[OK] $name"; else fail+=("$name"); echo "[FAIL] $name"; fi
}

pkg update -y || true
pkg upgrade -y || true
pkg install -y python git curl dnsutils openssl nmap golang ruby perl clang make pkg-config || true

# Official Go modules. Binaries are installed in $HOME/go/bin.
run_step "amass" go install github.com/owasp-amass/amass/v4/...@latest
run_step "assetfinder" go install github.com/tomnomnom/assetfinder@latest
run_step "dnsx" go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
run_step "gau" go install github.com/lc/gau/v2/cmd/gau@latest
run_step "gowitness" go install github.com/sensepost/gowitness@latest
run_step "hakrawler" go install github.com/hakluke/hakrawler@latest
run_step "httpx" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
run_step "katana" go install github.com/projectdiscovery/katana/cmd/katana@latest
run_step "nuclei" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
run_step "subfinder" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
run_step "waybackurls" go install github.com/tomnomnom/waybackurls@latest

# Python/Ruby tools where Termux provides the runtime.
run_step "wafw00f" python -m pip install --user --upgrade wafw00f
run_step "whatweb" gem install --user-install whatweb

# Source tools without executing any scan during installation.
if [[ ! -d "$HOME/tools/nikto/.git" ]]; then
  run_step "nikto" git clone --depth 1 https://github.com/sullo/nikto.git "$HOME/tools/nikto"
else
  run_step "nikto" git -C "$HOME/tools/nikto" pull --ff-only
fi
ln -sf "$HOME/tools/nikto/program/nikto.pl" "$PREFIX/bin/nikto" 2>/dev/null || true

if [[ ! -d "$HOME/tools/testssl.sh/.git" ]]; then
  run_step "testssl" git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$HOME/tools/testssl.sh"
else
  run_step "testssl" git -C "$HOME/tools/testssl.sh" pull --ff-only
fi
ln -sf "$HOME/tools/testssl.sh/testssl.sh" "$PREFIX/bin/testssl" 2>/dev/null || true

if [[ ! -d "$HOME/tools/exploitdb/.git" ]]; then
  run_step "searchsploit" git clone --depth 1 https://github.com/offensive-security/exploitdb.git "$HOME/tools/exploitdb"
else
  run_step "searchsploit" git -C "$HOME/tools/exploitdb" pull --ff-only
fi
if [[ -f "$HOME/tools/exploitdb/searchsploit" ]]; then
  chmod +x "$HOME/tools/exploitdb/searchsploit"
  ln -sf "$HOME/tools/exploitdb/searchsploit" "$PREFIX/bin/searchsploit" 2>/dev/null || true
fi

# sslscan may exist as a Termux package; do not build it silently if unavailable.
pkg install -y sslscan 2>/dev/null && ok+=("sslscan") || fail+=("sslscan")

# Refresh the command lookup and persist Go's bin directory for future sessions.
hash -r 2>/dev/null || true
touch "$HOME/.bashrc"
grep -qxF 'export PATH="$HOME/go/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"

# Nuclei templates are data, not an exploit runner; download only after the binary exists.
if command -v nuclei >/dev/null 2>&1; then
  run_step "nuclei-templates" nuclei -update-templates
fi

# ZAP baseline is optional and requires a Java/ZAP installation; report it clearly.
if command -v zap-baseline.py >/dev/null 2>&1; then ok+=("zap-baseline"); else fail+=("zap-baseline (install OWASP ZAP separately)"); fi

printf '\n===== تقرير التثبيت =====\n'
printf 'نجح:\n'; printf '  %s\n' "${ok[@]:-لا شيء}"
printf 'فشل أو يحتاج تثبيتًا يدويًا:\n'; printf '  %s\n' "${fail[@]:-لا شيء}"
printf '\nافحص الحالة من داخل المشروع:\n  python audit.py --tool-status\n'
