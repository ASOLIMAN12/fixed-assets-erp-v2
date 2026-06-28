require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_RECOVERY_EMAIL = process.env.ADMIN_RECOVERY_EMAIL || 'ahmededitor245@gmail.com';
const resetRequests = new Map();

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function mailReady() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function createTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || 'true') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

app.get('/api/health', (req, res) => res.json({ ok: true, app: 'Fixed Assets ERP Pro' }));

app.post('/api/request-reset', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    if (!username) return res.status(400).json({ error: 'اسم المستخدم مطلوب' });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const requestId = crypto.randomBytes(16).toString('hex');
    resetRequests.set(requestId, {
      username,
      code,
      expiresAt: Date.now() + 10 * 60 * 1000,
      attempts: 0
    });

    if (mailReady()) {
      const transporter = createTransport();
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: ADMIN_RECOVERY_EMAIL,
        subject: 'رمز استعادة كلمة مرور نظام الأصول الثابتة',
        text: `رمز استعادة كلمة المرور للمستخدم ${username} هو: ${code}\nالرمز صالح لمدة 10 دقائق.`,
        html: `<div dir="rtl" style="font-family:Tahoma,Arial"><h3>نظام الأصول الثابتة</h3><p>رمز استعادة كلمة المرور للمستخدم <b>${username}</b> هو:</p><h2>${code}</h2><p>الرمز صالح لمدة 10 دقائق.</p></div>`
      });
      return res.json({ ok: true, requestId, sentTo: ADMIN_RECOVERY_EMAIL });
    }

    return res.json({ ok: true, requestId, devCode: code, note: 'SMTP غير مضبوط. هذا كود تجريبي للاختبار المحلي فقط.' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/verify-reset', (req, res) => {
  const { requestId, username, code } = req.body || {};
  const rec = resetRequests.get(String(requestId || ''));
  if (!rec) return res.status(400).json({ error: 'طلب الاستعادة غير موجود' });
  if (Date.now() > rec.expiresAt) {
    resetRequests.delete(requestId);
    return res.status(400).json({ error: 'انتهت صلاحية الرمز' });
  }
  rec.attempts += 1;
  if (rec.attempts > 5) {
    resetRequests.delete(requestId);
    return res.status(400).json({ error: 'تم تجاوز عدد المحاولات' });
  }
  if (rec.username !== String(username || '').trim() || rec.code !== String(code || '').trim()) {
    return res.status(400).json({ error: 'رمز التحقق غير صحيح' });
  }
  resetRequests.delete(requestId);
  return res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Fixed Assets ERP Pro running on http://localhost:${PORT}`));
