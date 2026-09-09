'use strict';

const crypto = require('crypto');
const {promisify} = require('util');
const {Pool} = require('pg');

const scryptAsync = promisify(crypto.scrypt);
const SESSION_COOKIE = 'assetspro_session';
const SESSION_MS = 12 * 60 * 60 * 1000;
const OTP_MS = 10 * 60 * 1000;
const rate = new Map();

function normalizeEmail(value){return String(value || '').trim().toLowerCase()}
function normalizeUsername(value){return String(value || '').trim()}
function validEmail(value){return /^\S+@\S+\.\S+$/.test(value)}
function sha256(value){return crypto.createHash('sha256').update(String(value || '')).digest('hex')}
function safeText(value){return String(value || '').replace(/[<>&]/g, '')}

async function hashPassword(password){
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(String(password), salt, 64);
  return `scrypt$${salt.toString('hex')}$${Buffer.from(derived).toString('hex')}`;
}

async function verifyPassword(password, stored){
  if(String(stored || '').startsWith('sha256$')){
    const expectedHex = String(stored).slice(7);
    const actualHex = sha256(password);
    if(!/^[a-f0-9]{64}$/i.test(expectedHex))return false;
    return crypto.timingSafeEqual(Buffer.from(expectedHex, 'hex'), Buffer.from(actualHex, 'hex'));
  }
  const [type, saltHex, hashHex] = String(stored || '').split('$');
  if(type !== 'scrypt' || !saltHex || !hashHex)return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = Buffer.from(await scryptAsync(String(password), Buffer.from(saltHex, 'hex'), expected.length));
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function cookieValue(req, name){
  const raw = String(req.headers.cookie || '');
  for(const item of raw.split(';')){
    const pos = item.indexOf('=');
    if(pos < 0)continue;
    if(item.slice(0, pos).trim() === name)return decodeURIComponent(item.slice(pos + 1).trim());
  }
  return '';
}

function sessionCookie(token){
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_MS / 1000)}${secure}`;
}

function clearSessionCookie(){
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

function publicUser(row){
  return {
    id: Number(row.id),
    name: row.name,
    username: row.username,
    email: row.email,
    role: row.role,
    costCenter: row.cost_center || '',
    status: row.status,
    pages: Array.isArray(row.pages) ? row.pages : [],
    lastLogin: row.last_login ? new Date(row.last_login).toISOString() : ''
  };
}

function poolOptions(url){
  const options = {connectionString:url, max:5, idleTimeoutMillis:30000};
  try{
    const host = new URL(url).hostname;
    if(process.env.DATABASE_SSL === 'true' || (process.env.DATABASE_SSL !== 'false' && !host.endsWith('.internal'))){
      options.ssl = {rejectUnauthorized:false};
    }
  }catch(_){/* pg will return the useful configuration error */}
  return options;
}

async function sendEmail(to, subject, html){
  const apiKey = process.env.RESEND_API_KEY;
  const from = String(process.env.RECOVERY_FROM_EMAIL || '').trim();
  if(!apiKey || !from)throw Object.assign(new Error('خدمة البريد غير مهيأة على الخادم.'), {status:503});
  const response = await fetch('https://api.resend.com/emails', {
    method:'POST',
    headers:{Authorization:`Bearer ${apiKey}`, 'Content-Type':'application/json'},
    body:JSON.stringify({from, to:[to], subject, html})
  });
  if(!response.ok){
    const detail = await response.json().catch(() => ({}));
    console.error('Resend rejected email', response.status, detail?.name || '', detail?.message || '');
    throw Object.assign(new Error('رفض مزود البريد إرسال الرسالة. راجع Logs في Resend.'), {status:502});
  }
}

function rateLimit(key, milliseconds=60000){
  const now = Date.now(), last = rate.get(key) || 0;
  if(now - last < milliseconds)return false;
  rate.set(key, now);
  return true;
}

async function createCentralAuth(app, options={}){
  const databaseUrl = process.env.DATABASE_URL;
  const initialSetupKey = String(process.env.INITIAL_SETUP_KEY || '');
  let pool = options.pool || null;
  let configured = false;
  let initError = '';

  if(databaseUrl || pool){
    try{
      if(!pool)pool = new Pool(poolOptions(databaseUrl));
      await pool.query(`
        CREATE TABLE IF NOT EXISTS assetspro_users (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          username TEXT NOT NULL,
          username_key TEXT NOT NULL UNIQUE,
          email TEXT NOT NULL,
          email_key TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('Admin','Editor','Viewer')),
          cost_center TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL CHECK (status IN ('Active','Inactive')) DEFAULT 'Active',
          pages JSONB NOT NULL DEFAULT '[]'::jsonb,
          last_login TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS assetspro_sessions (
          token_hash TEXT PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES assetspro_users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS assetspro_sessions_expires_idx ON assetspro_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS assetspro_otps (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES assetspro_users(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL,
          code_hash TEXT NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          used_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS assetspro_otps_lookup_idx ON assetspro_otps(user_id,purpose,created_at DESC);
        CREATE TABLE IF NOT EXISTS assetspro_auth_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      configured = true;
      console.log('Assets Pro central authentication database is ready');
    }catch(error){
      initError = error.message;
      console.error('Central authentication database initialization failed:', error.message);
      if(pool){await pool.end().catch(() => {});pool = null}
    }
  }

  const dbRequired = (req, res, next) => {
    if(!configured || !pool)return res.status(503).json({ok:false,message:'قاعدة بيانات المستخدمين المركزية غير مهيأة. أضف DATABASE_URL في Render ثم أعد النشر.'});
    next();
  };

  async function sessionUser(req){
    if(!pool)return null;
    const token = cookieValue(req, SESSION_COOKIE);
    if(!token)return null;
    const result = await pool.query(`
      SELECT u.* FROM assetspro_sessions s
      JOIN assetspro_users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.status='Active'
    `, [sha256(token)]);
    return result.rows[0] || null;
  }

  const required = async(req, res, next) => {
    if(!configured || !pool)return dbRequired(req, res, next);
    try{
      const user = await sessionUser(req);
      if(!user)return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'});
      req.assetsProUser = user;
      next();
    }catch(error){next(error)}
  };

  const admin = async(req, res, next) => {
    if(!configured || !pool)return dbRequired(req, res, next);
    try{
      const user = await sessionUser(req);
      if(!user)return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'});
      if(user.role !== 'Admin')return res.status(403).json({ok:false,message:'هذه العملية متاحة لمدير النظام فقط.'});
      req.assetsProUser = user;
      next();
    }catch(error){next(error)}
  };

  const requirePage = page => async(req, res, next) => {
    if(!configured || !pool)return dbRequired(req, res, next);
    try{
      const user = await sessionUser(req);
      if(!user)return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'});
      if(user.role !== 'Admin' && !(Array.isArray(user.pages) && user.pages.includes(page))){
        return res.status(403).json({ok:false,message:'ليس لديك صلاحية لتنفيذ هذه العملية.'});
      }
      req.assetsProUser = user;
      next();
    }catch(error){next(error)}
  };

  async function consumeOtp(client, userId, purpose, code){
    const result = await client.query(`
      SELECT * FROM assetspro_otps
      WHERE user_id=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>NOW()
      ORDER BY created_at DESC LIMIT 1 FOR UPDATE
    `, [userId, purpose]);
    const otp = result.rows[0];
    if(!otp || otp.attempts >= 5 || !crypto.timingSafeEqual(Buffer.from(otp.code_hash), Buffer.from(sha256(code)))){
      if(otp)await client.query('UPDATE assetspro_otps SET attempts=attempts+1 WHERE id=$1', [otp.id]);
      return false;
    }
    await client.query('UPDATE assetspro_otps SET used_at=NOW() WHERE id=$1', [otp.id]);
    return true;
  }

  app.get('/api/auth/status', async(req, res) => {
    if(!configured || !pool)return res.json({ok:true,configured:false,initialized:false,error:initError ? 'database_connection_failed' : 'database_url_missing'});
    try{
      const result = await pool.query('SELECT EXISTS(SELECT 1 FROM assetspro_users) AS initialized');
      res.json({ok:true,configured:true,initialized:result.rows[0].initialized,setupReady:result.rows[0].initialized||initialSetupKey.length>=12,storage:'postgresql'});
    }catch(error){res.status(503).json({ok:false,configured:false,initialized:false,message:'تعذر الاتصال بقاعدة البيانات المركزية.'})}
  });

  app.post('/api/auth/setup', dbRequired, async(req, res, next) => {
    const name = String(req.body?.name || '').trim();
    const username = normalizeUsername(req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');
    const recovery = String(req.body?.recoveryCode || '');
    const providedSetupKey = String(req.body?.setupKey || '');
    const legacyUsers = Array.isArray(req.body?.legacyUsers) ? req.body.legacyUsers.slice(0, 1000) : [];
    if(initialSetupKey.length < 12)return res.status(503).json({ok:false,message:'أضف INITIAL_SETUP_KEY بطول 12 حرفًا على الأقل في Render ثم أعد النشر.'});
    if(!crypto.timingSafeEqual(Buffer.from(sha256(providedSetupKey),'hex'),Buffer.from(sha256(initialSetupKey),'hex'))){
      return res.status(403).json({ok:false,message:'مفتاح التهيئة المركزية غير صحيح.'});
    }
    if(!name || username.length < 3 || !validEmail(email) || password.length < 8 || recovery.length < 8){
      return res.status(400).json({ok:false,message:'أكمل البيانات الصحيحة. كلمة المرور ورمز الاستعادة لا يقلان عن 8 أحرف.'});
    }
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('assets-pro-first-admin'))");
      const count = await client.query('SELECT COUNT(*)::int AS count FROM assetspro_users');
      if(count.rows[0].count > 0){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'تمت تهيئة مدير النظام بالفعل. استخدم شاشة تسجيل الدخول.'})}
      const passwordHash = await hashPassword(password);
      const recoveryHash = await hashPassword(recovery);
      const created = await client.query(`
        INSERT INTO assetspro_users(name,username,username_key,email,email_key,password_hash,role,status,pages)
        VALUES($1,$2,$3,$4,$5,$6,'Admin','Active','[]'::jsonb) RETURNING *
      `, [name, username, username.toLowerCase(), email, email, passwordHash]);
      await client.query(`INSERT INTO assetspro_auth_settings(key,value) VALUES('recovery_hash',$1)
        ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`, [recoveryHash]);
      const usedNames = new Set([username.toLowerCase()]);
      const usedEmails = new Set([email]);
      let migratedUsers = 0;
      for(const legacy of legacyUsers){
        const legacyName = String(legacy?.name || '').trim();
        const legacyUsername = normalizeUsername(legacy?.username);
        const legacyUsernameKey = legacyUsername.toLowerCase();
        const legacyEmail = normalizeEmail(legacy?.email);
        const legacyHash = String(legacy?.passwordHash || '').trim().toLowerCase();
        if(!legacyName || legacyUsername.length < 3 || !validEmail(legacyEmail) || !/^[a-f0-9]{64}$/.test(legacyHash))continue;
        if(usedNames.has(legacyUsernameKey) || usedEmails.has(legacyEmail))continue;
        const legacyRole = ['Admin','Editor','Viewer'].includes(legacy?.role) ? legacy.role : 'Viewer';
        const legacyStatus = legacy?.status === 'Inactive' ? 'Inactive' : 'Active';
        const legacyPages = Array.isArray(legacy?.pages) ? [...new Set(legacy.pages.map(String))] : [];
        const legacyLastLogin = legacy?.lastLogin && !Number.isNaN(Date.parse(legacy.lastLogin)) ? new Date(legacy.lastLogin) : null;
        await client.query(`INSERT INTO assetspro_users(name,username,username_key,email,email_key,password_hash,role,cost_center,status,pages,last_login)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11) ON CONFLICT DO NOTHING`,
          [legacyName,legacyUsername,legacyUsernameKey,legacyEmail,legacyEmail,`sha256$${legacyHash}`,legacyRole,String(legacy?.costCenter||''),legacyStatus,JSON.stringify(legacyPages),legacyLastLogin]);
        usedNames.add(legacyUsernameKey);usedEmails.add(legacyEmail);migratedUsers++;
      }
      await client.query('COMMIT');
      res.status(201).json({ok:true,user:publicUser(created.rows[0]),migratedUsers});
    }catch(error){await client.query('ROLLBACK').catch(() => {});next(error)}finally{client.release()}
  });

  app.post('/api/auth/login', dbRequired, async(req, res, next) => {
    const username = normalizeUsername(req.body?.username).toLowerCase();
    const password = String(req.body?.password || '');
    if(!rateLimit(`login:${req.ip}:${username}`, 1500))return res.status(429).json({ok:false,message:'انتظر قليلًا قبل إعادة المحاولة.'});
    try{
      const result = await pool.query('SELECT * FROM assetspro_users WHERE username_key=$1', [username]);
      const user = result.rows[0];
      if(!user || user.status !== 'Active' || !await verifyPassword(password, user.password_hash)){
        return res.status(401).json({ok:false,message:'اسم المستخدم أو كلمة المرور غير صحيحة.'});
      }
      if(String(user.password_hash).startsWith('sha256$')){
        user.password_hash = await hashPassword(password);
        await pool.query('UPDATE assetspro_users SET password_hash=$1,updated_at=NOW() WHERE id=$2', [user.password_hash,user.id]);
      }
      const token = crypto.randomBytes(32).toString('base64url');
      await pool.query('DELETE FROM assetspro_sessions WHERE expires_at<=NOW()');
      await pool.query('INSERT INTO assetspro_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)', [sha256(token), user.id, new Date(Date.now()+SESSION_MS)]);
      const updated = await pool.query('UPDATE assetspro_users SET last_login=NOW(),updated_at=NOW() WHERE id=$1 RETURNING *', [user.id]);
      res.setHeader('Set-Cookie', sessionCookie(token));
      res.json({ok:true,user:publicUser(updated.rows[0])});
    }catch(error){next(error)}
  });

  app.post('/api/auth/logout', async(req, res, next) => {
    try{
      const token = cookieValue(req, SESSION_COOKIE);
      if(pool && token)await pool.query('DELETE FROM assetspro_sessions WHERE token_hash=$1', [sha256(token)]);
      res.setHeader('Set-Cookie', clearSessionCookie());
      res.json({ok:true});
    }catch(error){next(error)}
  });

  app.get('/api/auth/me', required, (req, res) => res.json({ok:true,user:publicUser(req.assetsProUser)}));

  app.get('/api/users', admin, async(req, res, next) => {
    try{
      const result = await pool.query('SELECT * FROM assetspro_users ORDER BY id');
      res.json({ok:true,users:result.rows.map(publicUser)});
    }catch(error){next(error)}
  });

  app.post('/api/auth/admin-approval/request', admin, async(req, res, next) => {
    const password = String(req.body?.password || '');
    const user = req.assetsProUser;
    if(!rateLimit(`admin-otp:${user.id}`))return res.status(429).json({ok:false,message:'انتظر دقيقة قبل إعادة إرسال رمز المصادقة.'});
    try{
      if(!await verifyPassword(password, user.password_hash))return res.status(401).json({ok:false,message:'كلمة مرور الأدمن الحالي غير صحيحة.'});
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      await sendEmail(user.email, 'Assets Pro — مصادقة تعديل حساب الأدمن', `<div dir="rtl" style="font-family:Arial"><h2>مصادقة تعديل حساب مدير النظام</h2><p>الأدمن الحالي: <b>${safeText(user.username)}</b></p><p>رمز المصادقة: <b style="font-size:24px;letter-spacing:4px">${code}</b></p><p>الرمز صالح لمدة 10 دقائق ويستخدم مرة واحدة.</p></div>`);
      await pool.query("UPDATE assetspro_otps SET used_at=NOW() WHERE user_id=$1 AND purpose='admin-change' AND used_at IS NULL", [user.id]);
      await pool.query("INSERT INTO assetspro_otps(user_id,purpose,code_hash,expires_at) VALUES($1,'admin-change',$2,$3)", [user.id, sha256(code), new Date(Date.now()+OTP_MS)]);
      res.json({ok:true,email:user.email.replace(/^(.{2}).*(@.*)$/, '$1***$2')});
    }catch(error){next(error)}
  });

  app.post('/api/users', admin, async(req, res, next) => {
    const id = Number(req.body?.id || 0);
    const name = String(req.body?.name || '').trim();
    const username = normalizeUsername(req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');
    const role = ['Admin','Editor','Viewer'].includes(req.body?.role) ? req.body.role : 'Viewer';
    const status = req.body?.status === 'Inactive' ? 'Inactive' : 'Active';
    const costCenter = String(req.body?.costCenter || '').trim();
    const pages = Array.isArray(req.body?.pages) ? [...new Set(req.body.pages.map(String))] : [];
    const approvalCode = String(req.body?.approvalCode || '').trim();
    if(!name || username.length < 3 || !validEmail(email) || (!id && password.length < 8) || (password && password.length < 8)){
      return res.status(400).json({ok:false,message:'أكمل البيانات الصحيحة. كلمة المرور لا تقل عن 8 أحرف.'});
    }
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const existingResult = id ? await client.query('SELECT * FROM assetspro_users WHERE id=$1 FOR UPDATE', [id]) : {rows:[]};
      const existing = existingResult.rows[0];
      if(id && !existing){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'المستخدم غير موجود.'})}
      const protectedChange = role === 'Admin' || existing?.role === 'Admin';
      if(protectedChange && !await consumeOtp(client, req.assetsProUser.id, 'admin-change', approvalCode)){
        await client.query('COMMIT');return res.status(403).json({ok:false,message:'رمز مصادقة الأدمن غير صحيح أو منتهي الصلاحية.'});
      }
      if(existing?.role === 'Admin' && (role !== 'Admin' || status !== 'Active')){
        const count = await client.query("SELECT COUNT(*)::int AS count FROM assetspro_users WHERE role='Admin' AND status='Active' AND id<>$1", [id]);
        if(count.rows[0].count === 0){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'لا يمكن إيقاف أو تخفيض صلاحية آخر مدير نظام نشط.'})}
      }
      let saved;
      if(existing){
        const passwordHash = password ? await hashPassword(password) : existing.password_hash;
        saved = await client.query(`UPDATE assetspro_users SET name=$1,username=$2,username_key=$3,email=$4,email_key=$5,
          password_hash=$6,role=$7,cost_center=$8,status=$9,pages=$10::jsonb,updated_at=NOW() WHERE id=$11 RETURNING *`,
          [name,username,username.toLowerCase(),email,email,passwordHash,role,costCenter,status,JSON.stringify(pages),id]);
      }else{
        saved = await client.query(`INSERT INTO assetspro_users(name,username,username_key,email,email_key,password_hash,role,cost_center,status,pages)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) RETURNING *`,
          [name,username,username.toLowerCase(),email,email,await hashPassword(password),role,costCenter,status,JSON.stringify(pages)]);
      }
      await client.query('COMMIT');
      res.json({ok:true,user:publicUser(saved.rows[0])});
    }catch(error){
      await client.query('ROLLBACK').catch(() => {});
      if(error.code === '23505')return res.status(409).json({ok:false,message:'اسم المستخدم أو البريد الإلكتروني مستخدم بالفعل.'});
      next(error);
    }finally{client.release()}
  });

  app.delete('/api/users/:id', admin, async(req, res, next) => {
    try{
      const target = await pool.query('SELECT * FROM assetspro_users WHERE id=$1', [Number(req.params.id)]);
      if(!target.rows[0])return res.status(404).json({ok:false,message:'المستخدم غير موجود.'});
      if(target.rows[0].role === 'Admin')return res.status(403).json({ok:false,message:'لا يمكن حذف حساب مدير النظام.'});
      await pool.query('DELETE FROM assetspro_users WHERE id=$1', [Number(req.params.id)]);
      res.json({ok:true});
    }catch(error){next(error)}
  });

  app.post('/api/auth/recovery/request', dbRequired, async(req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    if(!validEmail(email))return res.status(400).json({ok:false,message:'أدخل بريدًا إلكترونيًا صحيحًا.'});
    if(!rateLimit(`recovery:${email}`))return res.status(429).json({ok:false,message:'انتظر دقيقة قبل إعادة الإرسال.'});
    try{
      const found = await pool.query("SELECT * FROM assetspro_users WHERE email_key=$1 AND status='Active'", [email]);
      const user = found.rows[0];
      if(user){
        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        await sendEmail(user.email, 'Assets Pro — استعادة بيانات الدخول', `<div dir="rtl" style="font-family:Arial"><h2>استعادة بيانات الدخول</h2><p>اسم المستخدم: <b>${safeText(user.username)}</b></p><p>رمز التحقق: <b style="font-size:24px;letter-spacing:4px">${code}</b></p><p>صالح لمدة 10 دقائق.</p></div>`);
        await pool.query("UPDATE assetspro_otps SET used_at=NOW() WHERE user_id=$1 AND purpose='password-reset' AND used_at IS NULL", [user.id]);
        await pool.query("INSERT INTO assetspro_otps(user_id,purpose,code_hash,expires_at) VALUES($1,'password-reset',$2,$3)", [user.id, sha256(code), new Date(Date.now()+OTP_MS)]);
      }
      res.json({ok:true,message:'إذا كان البريد مسجلًا فستصل رسالة الاستعادة.'});
    }catch(error){next(error)}
  });

  app.post('/api/auth/recovery/reset', dbRequired, async(req, res, next) => {
    const username = normalizeUsername(req.body?.username).toLowerCase();
    const code = String(req.body?.code || '');
    const password = String(req.body?.password || '');
    if(!username || code.length < 6 || password.length < 8)return res.status(400).json({ok:false,message:'تحقق من اسم المستخدم والرمز وكلمة المرور الجديدة.'});
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const found = await client.query('SELECT * FROM assetspro_users WHERE username_key=$1 FOR UPDATE', [username]);
      const user = found.rows[0];
      let valid = false;
      if(user)valid = await consumeOtp(client, user.id, 'password-reset', code);
      if(!valid && user){
        const setting = await client.query("SELECT value FROM assetspro_auth_settings WHERE key='recovery_hash'");
        valid = !!setting.rows[0] && await verifyPassword(code, setting.rows[0].value);
      }
      if(!user || !valid){await client.query('COMMIT');return res.status(403).json({ok:false,message:'رمز الاستعادة أو رمز البريد غير صحيح أو انتهت صلاحيته.'})}
      await client.query("UPDATE assetspro_users SET password_hash=$1,status='Active',updated_at=NOW() WHERE id=$2", [await hashPassword(password), user.id]);
      await client.query('DELETE FROM assetspro_sessions WHERE user_id=$1', [user.id]);
      await client.query('COMMIT');
      res.json({ok:true});
    }catch(error){await client.query('ROLLBACK').catch(() => {});next(error)}finally{client.release()}
  });

  app.post('/api/auth/recovery-code', admin, async(req, res, next) => {
    const password = String(req.body?.password || '');
    const recoveryCode = String(req.body?.recoveryCode || '');
    if(recoveryCode.length < 8)return res.status(400).json({ok:false,message:'رمز الاستعادة يجب ألا يقل عن 8 أحرف أو أرقام.'});
    try{
      if(!await verifyPassword(password, req.assetsProUser.password_hash))return res.status(401).json({ok:false,message:'كلمة مرور الأدمن غير صحيحة.'});
      await pool.query(`INSERT INTO assetspro_auth_settings(key,value) VALUES('recovery_hash',$1)
        ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`, [await hashPassword(recoveryCode)]);
      res.json({ok:true});
    }catch(error){next(error)}
  });

  return {configured, required, admin, requirePage, sessionUser, publicUser};
}

module.exports = {createCentralAuth};
