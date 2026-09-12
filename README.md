# Termux Web Audit Framework

إطار قابل للتوسعة لفحص مواقع **تملكها أو لديك تصريح مكتوب لاختبارها** من Termux. يجمع مؤشرات دفاعية منخفضة التأثير، يوحّد النتائج، ويقدّر الخطورة دون استغلال الثغرات.

> **تنبيه قانوني:** لا تستخدم هذا المشروع ضد أهداف عامة أو دون تفويض. أنت مسؤول عن النطاق، معدل الطلبات، والالتزام بالقوانين وسياسات مزود الخدمة.

## الأدوات المدعومة

يعرض الأمر التالي كل ملفات التشغيل الثابتة:

```bash
python audit.py --list-tools
```

وتشمل حاليًا: `amass`, `assetfinder`, `curl`, `dig`, `dnsx`, `host`, `httpx`, `nikto`, `nmap`, `nuclei`, `openssl`, `searchsploit`, `sslscan`, `subfinder`, `testssl`, `wafw00f`, و`whatweb`.

الأدوات غير المثبتة يتم تخطيها مع تسجيل ملاحظة في التقرير. لا يمرر الإطار خيارات عشوائية إلى الأدوات؛ كل أداة لها ملف تشغيل ثابت منخفض التأثير.

## التثبيت على Termux

```bash
pkg update
pkg install -y python git curl dnsutils openssl nmap

git clone https://github.com/Mohmmedaa11/termux-web-audit-framework.git
cd termux-web-audit-framework
chmod +x audit.py
```

ثبّت الأدوات الإضافية من مصادرها الرسمية فقط، وراجع تراخيصها وإعداداتها قبل استخدامها. لا يلزم تثبيت كل الأدوات.

## الاستخدام الآمن

1. أنشئ قائمة بالنطاقات المصرح بها فقط:

```bash
cp config/scope.txt.example config/scope.txt
nano config/scope.txt
```

2. شغّل الفحص الأساسي:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports
```

3. شغّل أداة محددة:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports --tool httpx
```

4. شغّل كل ملفات الأدوات المثبتة محليًا. هذا الخيار قد ينفذ عدة اتصالات، لذلك استخدمه فقط في نافذة اختبار مصرح بها:

```bash
python audit.py scan --target https://staging.example.com \
  --scope config/scope.txt --out reports --all --timeout 90
```

المخرجات:

- `reports/report.json`: نتائج منظمة.
- `reports/report.md`: تقرير قابل للقراءة.
- `reports/raw/`: مخرجات كل أداة.

## تقييم الخطورة

- **Critical:** مؤشر شديد يحتاج تحققًا يدويًا فوريًا.
- **High:** ضعف مهم قد يؤدي إلى أثر كبير عند جمعه مع عوامل أخرى.
- **Medium:** إعداد أو كشف معلومات يحتاج معالجة مخططة.
- **Low / Info:** تحسينات أو ملاحظات سياقية.

الدرجات ليست إثباتًا لوجود ثغرة. يجب التحقق يدويًا، وتوثيق التصريح، وإعادة الاختبار بعد الإصلاح.

## ما لا يفعله الإطار

هذا المشروع لا ينفذ exploit، ولا يتجاوز المصادقة، ولا يجمع كلمات مرور، ولا يخمن كلمات المرور، ولا يطلق brute force، ولا يفتح فحصًا واسعًا تلقائيًا، ولا يدعم خيارات هجومية يمررها المستخدم. أدوات اكتشاف المحتوى عالية المعدل وأدوات الاستغلال متعمدة خارج النطاق.

## الاختبار المحلي

```bash
make test
```

## الترخيص

MIT — راجع `LICENSE`، مع بقاء مسؤولية الاستخدام المصرح به على المشغّل.
