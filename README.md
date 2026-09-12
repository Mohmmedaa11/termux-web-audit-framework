# Termux Web Audit Framework

إطار قابل للتوسعة لفحص مواقع **تملكها أو لديك تصريح مكتوب لاختبارها** من Termux. يجمع مؤشرات دفاعية منخفضة التأثير، يوحّد النتائج، ويقدّر الخطورة دون استغلال الثغرات.

> **تنبيه قانوني:** لا تستخدم المشروع ضد أهداف عامة أو دون تفويض. أنت مسؤول عن النطاق، معدل الطلبات، والالتزام بالقوانين وسياسات مزود الخدمة.

## المزايا الحالية

- تأكيد تصريح لمرة واحدة داخل جلسة التشغيل، دون حفظ قائمة نطاقات.
- فحص هدف واحد أو عدة أهداف من ملف.
- فحص ترويسات HTTP، DNS، TLS، وملفات `robots.txt` و`security.txt`.
- تشغيل ملفات ثابتة لأدوات اكتشاف وفحص منخفضة التأثير.
- درجة مخاطر من 0 إلى 100، مع JSON وMarkdown وCSV.
- `--dry-run` لمراجعة أوامر الأدوات قبل التنفيذ.
- عزل المخرجات الخام لكل نطاق.
- قائمة فحص يدوية شاملة في `manual-checklist.md`.

## الأدوات المدعومة

```bash
python audit.py --list-tools
```

تشمل: `amass`, `assetfinder`, `curl`, `dig`, `dnsx`, `gau`, `gowitness`, `hakrawler`, `host`, `httpx`, `katana`, `nikto`, `nmap`, `nuclei`, `openssl`, `searchsploit`, `sslscan`, `subfinder`, `testssl`, `wafw00f`, `waybackurls`, `whatweb`، و`zap-baseline` عند تثبيت OWASP ZAP.

الأدوات غير المثبتة يتم تخطيها مع تسجيل ملاحظة في التقرير. لا يمرر الإطار خيارات عشوائية؛ لكل أداة ملف تشغيل ثابت.

## التثبيت على Termux

ثبّت Termux من [F-Droid](https://f-droid.org/packages/com.termux/) أو من [إصدارات GitHub الرسمية](https://github.com/termux/termux-app/releases)، وليس من نسخة Play Store القديمة. راجع [توثيق إدارة الحزم الرسمي](https://github.com/termux/termux-packages/wiki/Package-Management) عند حدوث مشكلة في المستودعات.

```bash
pkg update
pkg upgrade -y
pkg install -y python git curl dnsutils openssl nmap

git clone https://github.com/Mohmmedaa11/termux-web-audit-framework.git
cd termux-web-audit-framework
chmod +x audit.py
```

أو نفّذ المثبت الموجود داخل المشروع:

```bash
chmod +x install-termux.sh
./install-termux.sh
```

ثبّت الأدوات الإضافية من مصادرها الرسمية فقط، وراجع تراخيصها وإعداداتها قبل استخدامها.

تثبيت كل أداة خارجية ليس مطلوبًا ولا يُنصح به تلقائيًا؛ استخدم فقط الأدوات التي تحتاجها وتأكد من توافقها مع Termux.

## الإعداد والفحص

### التشغيل التفاعلي: أدخل رابط الموقع أثناء التشغيل

شغّل مباشرة:

```bash
python audit.py interactive --out reports
```

سيظهر prompt لإدخال الرابط. اكتب مثلًا:

```text
https://staging.example.com
```

سيطلب البرنامج تأكيد التصريح بكتابة `I_HAVE_PERMISSION` مرة واحدة داخل الجلسة، ولا يحفظ أي نطاقات على القرص. للخروج اكتب `exit`.

لتشغيل الأدوات المثبتة ضمن الوضع التفاعلي:

```bash
python audit.py interactive --out reports --all
```

فحص هدف واحد:

```bash
python audit.py scan --target https://staging.example.com \
  --out reports
```

فحص عدة أهداف مذكورة في ملف:

```bash
cat > targets.txt <<'EOF'
https://app.example.com
https://api.example.com
EOF
python audit.py scan --targets-file targets.txt \
  --out reports
```

تشغيل أداة محددة أو جميع الأدوات المثبتة:

```bash
python audit.py scan --target https://staging.example.com \
  --out reports --tool httpx

python audit.py scan --target https://staging.example.com \
  --out reports --all --timeout 90
```

راجع الأوامر قبل التنفيذ:

```bash
python audit.py scan --target https://staging.example.com \
  --out reports --all --dry-run
```

## خطة الفحص اليدوي

لتوليد خطة حسب طبيعة التطبيق دون أي اتصال شبكي:

```bash
python manual_plan.py --type web --type api --type auth --type business \
  --out manual-plan.md
```

ينتج الأمر `manual-plan.md` و`manual-plan.json`. كما توجد قائمة تفصيلية ثابتة في [manual-checklist.md](manual-checklist.md). الأدوات الآلية لا تستطيع إثبات سلامة منطق الأعمال أو التفويض أو الحالات المخفية؛ سجّل الدليل والنتيجة لكل بند يدويًا.

## المخرجات

- `reports/report.json`: نتائج منظمة قابلة للمعالجة.
- `reports/report.md`: تقرير قابل للقراءة.
- `reports/report.csv`: جدول مناسب للفرز والتحليل.
- `reports/raw/<hostname>/`: مخرجات الأدوات الخام لكل هدف.

## التغطية والقيود

راجع [مصفوفة التغطية](docs/coverage.md). الإطار لا يستطيع ضمان اكتشاف جميع الثغرات «المخفية»؛ فهو لا يختبر منطق الأعمال، التفويض، كل حالات المصادقة، أو الثغرات التي تحتاج استغلالًا. أي نتيجة آلية تحتاج تحققًا يدويًا ضمن التفويض.

للتوثيق اليدوي استخدم [قائمة الفحص اليدوي](manual-checklist.md)، خصوصًا لاختبارات المصادقة، التفويض، IDOR، منطق الأعمال، CSRF، SSRF، رفع الملفات، وسلسلة التوريد.

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
