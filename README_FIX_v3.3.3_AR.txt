Assets Pro v3.3.3 — Hosted Mode Fix

تم إصلاح رسالة showDirectoryPicker عند التشغيل على Render/HTTPS.
في وضع HTTPS:
- لا يتم طلب اختيار مجلد محلي تلقائيًا.
- Master Data يتم تحميله وحفظه عبر Central API.
- فتح HR Pro يذهب إلى /hr.html.
- أزرار ربط المجلد المحلي تُخفى لأنها غير مطلوبة على الخادم.
في وضع file:// المحلي تبقى وظائف المجلد كما هي.

للمستودع الحالي الذي يحتوي index.html وhr.html في Root:
استخدم الحزمة GitHub_Flat، وارفع الملفات إلى جذر المستودع.
