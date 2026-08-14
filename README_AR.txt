Assets Pro v3.3.2 — HTTPS / Central Server

الهدف:
- فتح Assets Pro من iPhone/Android عبر HTTPS.
- تشغيل الكاميرا للجرد.
- Master Data مركزي واحد لكل الأجهزة.
- حفظ نتائج الجرد مركزيًا.
- نسخ احتياطية تلقائية قبل كل تحديث مركزي.

تشغيل محلي:
1) ثبّت Node.js.
2) افتح Terminal داخل المجلد.
3) npm install
4) npm start
5) افتح http://localhost:3000

على الهاتف:
- يجب نشر الحزمة على HTTPS (مثل Render) أو استخدام Reverse Proxy/HTTPS داخل الشبكة.
- بعد النشر افتح الرابط من الهاتف.
- اضغط الجرد والباركود > تشغيل الكاميرا.

ملفات مهمة:
- public/index.html = Assets Pro
- public/hr.html = HR Pro
- data/Assets_Master_Data.json = البيانات المركزية
- data/inventory.json = نتائج الجرد
- data/backups = النسخ الاحتياطية التلقائية

مهم:
هذه الحزمة جاهزة للنشر، لكنها لا تُنشئ رابطًا عامًا تلقائيًا. يلزم رفعها إلى خدمة استضافة مثل Render أو خادمك.
