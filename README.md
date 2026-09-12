# Termux Web Audit Framework

إطار قابل للتوسعة لفحص مواقع **تملكها أو لديك تصريح مكتوب لاختبارها** من Termux. يجمع مؤشرات دفاعية منخفضة التأثير، يوحّد النتائج، ويقدّر الخطورة دون استغلال الثغرات.

> **تنبيه قانوني:** لا تستخدم المشروع ضد أهداف عامة أو دون تفويض. أنت مسؤول عن النطاق، معدل الطلبات، والالتزام بالقوانين وسياسات مزود الخدمة.

## المزايا الحالية

- قائمة سماح إلزامية للنطاقات.
- فحص هدف واحد أو عدة أهداف من ملف.
- فحص ترويسات HTTP، DNS، TLS، وملفات `robots.txt` و`security.txt`.
- تشغيل ملفات ثابتة لأدوات اكتشاف وفحص منخفضة التأثير.
- درجة مخاطر من 0 إلى 100، مع JSON وMarkdown وCSV.
- `--dry-run` لمراجعة أوامر الأدوات قبل التنفيذ.
- عزل المخرجات الخام لكل نطاق.

## الأدوات المدعومة

```bash
python audit.py --list-tools
```

تشمل: `amass`, `assetfinder`, `curl`, `dig`, `dnsx`, `host`, `httpx`, `nikto`, `nmap`, `nuclei`, `openssl`, `searchsploit`, `sslscan`, `subfinder`, `testssl`, `wafw00f`, و`whatweb`.

الأدوات غير المثبتة يتم تخطيها مع تسجيل ملاحظة في التقرير. لا يمرر الإطار خيارات عشوائية؛ لكل أداة ملف تشغيل ثابت.

## التثبيت على Termux

```bash
pkg update
pkg install -y python git curl dnsutils openssl nmap

git clone https://github.com/Mohmmedaa11/termux-web-audit-framework.git
cd termux-web-audit-framework
chmod +x audit.py
```

ثبّت الأدوات الإضافية من مصادرها الرسمية فقط، وراجع تراخيصها وإعداداتها قبل استخدامها.

## الإعداد والفحص

أنشئ قائمة النطاقات المصرح بها:

```bash
cp config/scope.txt.example config/scope.txt
nano config/scope.txt
```

فحص هدف واحد:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports
```

فحص عدة أهداف مذكورة في ملف:

```bash
cat > targets.txt <<'EOF'
https://app.example.com
https://api.example.com
EOF
python audit.py scan --targets-file targets.txt \
  --scope config/scope.txt --out reports
```

تشغيل أداة محددة أو جميع الأدوات المثبتة:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports --tool httpx

python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports --all --timeout 90
```

راجع الأوامر قبل التنفيذ:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports --all --dry-run
```

## المخرجات

- `reports/report.json`: نتائج منظمة قابلة للمعالجة.
- `reports/report.md`: تقرير قابل للقراءة.
- `reports/report.csv`: جدول مناسب للفرز والتحليل.
- `reports/raw/<hostname>/`: مخرجات الأدوات الخام لكل هدف.

## تقييم الخطورة

- **Critical:** مؤشر شديد يحتاج تحققًا يدويًا فوريًا.
- **High:** ضعف مهم قد يؤدي إلى أثر كبير عند جمعه مع عوامل أخرى.
- **Medium:** إعداد أو كشف معلومات يحتاج معالجة مخططة.
- **Low / Info:** تحسينات أو ملاحظات سياقية.

الدرجة رقم إرشادي وليست إثباتًا لوجود ثغرة. يجب التحقق يدويًا، وتوثيق التصريح، وإعادة الاختبار بعد الإصلاح.

## ما لا يفعله الإطار

لا ينفذ exploit، ولا يتجاوز المصادقة، ولا يجمع كلمات مرور، ولا يخمنها، ولا يطلق brute force، ولا يفتح فحصًا واسعًا تلقائيًا، ولا يدعم خيارات هجومية يمررها المستخدم. أدوات اكتشاف المحتوى عالية المعدل وأدوات الاستغلال متعمدة خارج النطاق.

## الاختبار المحلي

```bash
make test
```

## الترخيص

MIT — راجع `LICENSE`، مع بقاء مسؤولية الاستخدام المصرح به على المشغّل.
