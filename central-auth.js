'use strict';

const crypto = require('crypto');
const {promisify} = require('util');
const {Pool} = require('pg');

const scryptAsync = promisify(crypto.scrypt);
const SESSION_MS = Math.min(24, Math.max(1, Number(process.env.SESSION_HOURS || 8))) * 60 * 60 * 1000;
const OTP_MS = 10 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const MAX_LOGIN_FAILURES = 5;
const rate = new Map();

function normalizeEmail(value){return String(value || '').trim().toLowerCase()}
function normalizeUsername(value){return String(value || '').trim()}
function validEmail(value){return /^\S+@\S+\.\S+$/.test(value)}
function sha256(value){return crypto.createHash('sha256').update(String(value || '')).digest('hex')}
function safeText(value){return String(value || '').replace(/[<>&]/g, '')}
function validPassword(value){
  const text = String(value || '');
  return text.length >= 12 && text.length <= 128 && /\p{L}/u.test(text) && /\d/u.test(text);
}
function validDeviceId(value){return /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(String(value||''))}
function boundedInteger(value,min,max,fallback){const n=Number(value);return Number.isFinite(n)?Math.min(max,Math.max(min,Math.round(n))):fallback}

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

function sessionCookieName(){return process.env.NODE_ENV === 'production' ? '__Host-assetspro_session' : 'assetspro_session'}

function sessionCookie(token){
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${sessionCookieName()}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_MS / 1000)}${secure}`;
}

function clearSessionCookie(){
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${sessionCookieName()}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
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

function rateLimit(key, milliseconds=60000, maxAttempts=1){
  const now = Date.now();
  if(rate.size > 10000){for(const [item,value] of rate){if(value.resetAt <= now)rate.delete(item)}}
  let entry = rate.get(key);
  if(!entry || entry.resetAt <= now)entry = {count:0,resetAt:now+milliseconds};
  entry.count += 1;rate.set(key,entry);
  return entry.count <= maxAttempts;
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
          failed_login_attempts INTEGER NOT NULL DEFAULT 0,
          last_failed_login TIMESTAMPTZ,
          login_locked_until TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE assetspro_users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE assetspro_users ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMPTZ;
        ALTER TABLE assetspro_users ADD COLUMN IF NOT EXISTS login_locked_until TIMESTAMPTZ;
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
        CREATE TABLE IF NOT EXISTS assetspro_security_events (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT REFERENCES assetspro_users(id) ON DELETE SET NULL,
          event_type TEXT NOT NULL,
          success BOOLEAN NOT NULL DEFAULT FALSE,
          username_key TEXT NOT NULL DEFAULT '',
          ip_address TEXT NOT NULL DEFAULT '',
          request_id TEXT NOT NULL DEFAULT '',
          details JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS assetspro_security_events_created_idx ON assetspro_security_events(created_at DESC);
        CREATE TABLE IF NOT EXISTS assetspro_device_enrollment_tokens (
          token_hash TEXT PRIMARY KEY,
          created_by BIGINT NOT NULL REFERENCES assetspro_users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          used_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS assetspro_devices (
          device_id TEXT PRIMARY KEY,
          secret_hash TEXT NOT NULL,
          device_name TEXT NOT NULL,
          os_version TEXT NOT NULL DEFAULT '',
          agent_version TEXT NOT NULL DEFAULT '',
          defender_enabled BOOLEAN NOT NULL DEFAULT FALSE,
          realtime_enabled BOOLEAN NOT NULL DEFAULT FALSE,
          firewall_enabled BOOLEAN NOT NULL DEFAULT FALSE,
          bitlocker_status TEXT NOT NULL DEFAULT 'unknown',
          tamper_protected BOOLEAN NOT NULL DEFAULT FALSE,
          signature_age_days INTEGER NOT NULL DEFAULT 999,
          failed_logons_24h INTEGER NOT NULL DEFAULT 0,
          rdp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
          risk_score INTEGER NOT NULL DEFAULT 100,
          alerts JSONB NOT NULL DEFAULT '[]'::jsonb,
          last_ip TEXT NOT NULL DEFAULT '',
          last_seen TIMESTAMPTZ,
          enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS assetspro_devices_last_seen_idx ON assetspro_devices(last_seen DESC);
      `);
      await pool.query("DELETE FROM assetspro_security_events WHERE created_at < NOW() - INTERVAL '90 days'").catch(() => {});
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

  async function audit(req, eventType, success, {userId=null, username='', details={}}={}){
    if(!pool)return;
    const cleanDetails = details && typeof details === 'object' ? details : {};
    await pool.query(`INSERT INTO assetspro_security_events(user_id,event_type,success,username_key,ip_address,request_id,details)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`,[
      userId,eventType,!!success,normalizeUsername(username).toLowerCase(),String(req.ip||'').slice(0,80),String(req.requestId||'').slice(0,80),JSON.stringify(cleanDetails)
    ]).catch(error=>console.error('Security audit write failed:',error.message));
  }

  function publicDevice(row){
    return {
      deviceId:row.device_id,deviceName:row.device_name,osVersion:row.os_version,agentVersion:row.agent_version,
      defenderEnabled:!!row.defender_enabled,realtimeEnabled:!!row.realtime_enabled,firewallEnabled:!!row.firewall_enabled,
      bitlockerStatus:row.bitlocker_status,tamperProtected:!!row.tamper_protected,signatureAgeDays:Number(row.signature_age_days),
      failedLogons24h:Number(row.failed_logons_24h),rdpEnabled:!!row.rdp_enabled,riskScore:Number(row.risk_score),
      alerts:Array.isArray(row.alerts)?row.alerts:[],lastSeen:row.last_seen?new Date(row.last_seen).toISOString():'',
      enrolledAt:row.enrolled_at?new Date(row.enrolled_at).toISOString():''
    };
  }

  const deviceRequired = async(req,res,next) => {
    if(!configured || !pool)return dbRequired(req,res,next);
    if(!rateLimit(`device-auth:${req.ip}`,15*60*1000,120))return res.status(429).json({ok:false,message:'تم تجاوز معدل اتصال أجهزة الحماية.'});
    const authorization=String(req.headers.authorization||'');
    const secret=authorization.startsWith('Bearer ')?authorization.slice(7).trim():'';
    const deviceId=String(req.body?.deviceId||req.headers['x-assetspro-device-id']||'').trim();
    if(!validDeviceId(deviceId)||secret.length<32||secret.length>256)return res.status(401).json({ok:false,message:'هوية جهاز الحماية غير صالحة.'});
    try{
      const result=await pool.query('SELECT * FROM assetspro_devices WHERE device_id=$1',[deviceId]);
      const device=result.rows[0];
      const actual=Buffer.from(sha256(secret),'hex');
      const expected=device&&/^[a-f0-9]{64}$/i.test(device.secret_hash)?Buffer.from(device.secret_hash,'hex'):crypto.randomBytes(32);
      if(!device||!crypto.timingSafeEqual(actual,expected)){
        await audit(req,'device_auth_failed',false,{details:{deviceId:validDeviceId(deviceId)?deviceId:'invalid'}});
        return res.status(401).json({ok:false,message:'تعذر التحقق من جهاز الحماية.'});
      }
      req.assetsProDevice=device;next();
    }catch(error){next(error)}
  };

  async function sessionUser(req){
    if(!pool)return null;
    const token = cookieValue(req, sessionCookieName());
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
      if(!user){await audit(req,'access_denied',false,{details:{reason:'no_session',path:req.path}});return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'})}
      req.assetsProUser = user;
      next();
    }catch(error){next(error)}
  };

  const admin = async(req, res, next) => {
    if(!configured || !pool)return dbRequired(req, res, next);
    try{
      const user = await sessionUser(req);
      if(!user){await audit(req,'access_denied',false,{details:{reason:'no_session',path:req.path}});return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'})}
      if(user.role !== 'Admin'){await audit(req,'access_denied',false,{userId:user.id,username:user.username,details:{reason:'admin_required',path:req.path}});return res.status(403).json({ok:false,message:'هذه العملية متاحة لمدير النظام فقط.'})}
      req.assetsProUser = user;
      next();
    }catch(error){next(error)}
  };

  const requirePage = page => async(req, res, next) => {
    if(!configured || !pool)return dbRequired(req, res, next);
    try{
      const user = await sessionUser(req);
      if(!user){await audit(req,'access_denied',false,{details:{reason:'no_session',path:req.path,page}});return res.status(401).json({ok:false,message:'انتهت جلسة الدخول. سجل الدخول مرة أخرى.'})}
      if(user.role !== 'Admin' && !(Array.isArray(user.pages) && user.pages.includes(page))){
        await audit(req,'access_denied',false,{userId:user.id,username:user.username,details:{reason:'page_permission',path:req.path,page}});
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
      res.json({ok:true,configured:true,initialized:result.rows[0].initialized,setupReady:result.rows[0].initialized||initialSetupKey.length>=16,storage:'postgresql'});
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
    if(!rateLimit(`setup:${req.ip}`,15*60*1000,10))return res.status(429).json({ok:false,message:'تم تجاوز محاولات التهيئة المسموحة. حاول لاحقًا.'});
    if(initialSetupKey.length < 16)return res.status(503).json({ok:false,message:'أضف INITIAL_SETUP_KEY بطول 16 حرفًا على الأقل في Render ثم أعد النشر.'});
    if(!crypto.timingSafeEqual(Buffer.from(sha256(providedSetupKey),'hex'),Buffer.from(sha256(initialSetupKey),'hex'))){
      return res.status(403).json({ok:false,message:'مفتاح التهيئة المركزية غير صحيح.'});
    }
    if(!name || username.length < 3 || username.length > 80 || !validEmail(email) || !validPassword(password) || !validPassword(recovery)){
      return res.status(400).json({ok:false,message:'أكمل البيانات الصحيحة. كلمة المرور ورمز الاستعادة يجب أن يكونا من 12 حرفًا على الأقل ويحتويان على حرف ورقم.'});
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
      await audit(req,'system_initialized',true,{userId:created.rows[0].id,username,details:{migratedUsers}});
      res.status(201).json({ok:true,user:publicUser(created.rows[0]),migratedUsers});
    }catch(error){await client.query('ROLLBACK').catch(() => {});next(error)}finally{client.release()}
  });

  app.post('/api/auth/login', dbRequired, async(req, res, next) => {
    const username = normalizeUsername(req.body?.username).toLowerCase();
    const password = String(req.body?.password || '');
    if(!username || username.length > 80 || !password || password.length > 128)return res.status(400).json({ok:false,message:'تحقق من بيانات الدخول.'});
    if(!rateLimit(`login:${req.ip}:${username}`, LOGIN_WINDOW_MS, 20)){
      await audit(req,'login_rate_limited',false,{username});
      return res.status(429).json({ok:false,message:'تم تجاوز عدد محاولات الدخول. حاول مرة أخرى بعد 15 دقيقة.'});
    }
    try{
      const result = await pool.query('SELECT * FROM assetspro_users WHERE username_key=$1', [username]);
      const user = result.rows[0];
      if(user?.login_locked_until && new Date(user.login_locked_until).getTime() > Date.now()){
        const retryAfter = Math.max(1,Math.ceil((new Date(user.login_locked_until).getTime()-Date.now())/1000));
        res.setHeader('Retry-After',String(retryAfter));
        await audit(req,'login_locked',false,{userId:user.id,username,details:{retryAfter}});
        return res.status(429).json({ok:false,message:'تم إيقاف تسجيل الدخول مؤقتًا بسبب محاولات متكررة. حاول بعد 15 دقيقة.'});
      }
      if(!user || user.status !== 'Active' || !await verifyPassword(password, user.password_hash)){
        if(user){
          const last = user.last_failed_login ? new Date(user.last_failed_login).getTime() : 0;
          const failures = Date.now()-last > LOGIN_WINDOW_MS ? 1 : Number(user.failed_login_attempts||0)+1;
          const lockedUntil = failures >= MAX_LOGIN_FAILURES ? new Date(Date.now()+LOGIN_LOCK_MS) : null;
          await pool.query('UPDATE assetspro_users SET failed_login_attempts=$1,last_failed_login=NOW(),login_locked_until=$2,updated_at=NOW() WHERE id=$3',[failures,lockedUntil,user.id]);
          await audit(req,lockedUntil?'login_lockout':'login_failed',false,{userId:user.id,username,details:{attempt:failures}});
        }else await audit(req,'login_failed',false,{username,details:{reason:'unknown_user'}});
        return res.status(401).json({ok:false,message:'اسم المستخدم أو كلمة المرور غير صحيحة.'});
      }
      if(String(user.password_hash).startsWith('sha256$')){
        user.password_hash = await hashPassword(password);
        await pool.query('UPDATE assetspro_users SET password_hash=$1,updated_at=NOW() WHERE id=$2', [user.password_hash,user.id]);
      }
      const token = crypto.randomBytes(32).toString('base64url');
      await pool.query('DELETE FROM assetspro_sessions WHERE expires_at<=NOW()');
      await pool.query('INSERT INTO assetspro_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)', [sha256(token), user.id, new Date(Date.now()+SESSION_MS)]);
      const updated = await pool.query('UPDATE assetspro_users SET last_login=NOW(),failed_login_attempts=0,last_failed_login=NULL,login_locked_until=NULL,updated_at=NOW() WHERE id=$1 RETURNING *', [user.id]);
      await pool.query(`DELETE FROM assetspro_sessions WHERE token_hash IN (
        SELECT token_hash FROM assetspro_sessions WHERE user_id=$1 ORDER BY created_at DESC OFFSET 5
      )`,[user.id]);
      await audit(req,'login_success',true,{userId:user.id,username});
      res.setHeader('Set-Cookie', sessionCookie(token));
      res.json({ok:true,user:publicUser(updated.rows[0])});
    }catch(error){next(error)}
  });

  app.post('/api/auth/logout', async(req, res, next) => {
    try{
      const token = cookieValue(req, sessionCookieName());
      let user = null;if(pool && token)user = await sessionUser(req);
      if(pool && token)await pool.query('DELETE FROM assetspro_sessions WHERE token_hash=$1', [sha256(token)]);
      if(user)await audit(req,'logout',true,{userId:user.id,username:user.username});
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
    if(!rateLimit(`admin-otp:${user.id}`,15*60*1000,5))return res.status(429).json({ok:false,message:'تم تجاوز عدد رسائل المصادقة. حاول لاحقًا.'});
    try{
      if(!await verifyPassword(password, user.password_hash)){await audit(req,'admin_otp_denied',false,{userId:user.id,username:user.username});return res.status(401).json({ok:false,message:'كلمة مرور الأدمن الحالي غير صحيحة.'})}
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      await sendEmail(user.email, 'Assets Pro — مصادقة تعديل حساب الأدمن', `<div dir="rtl" style="font-family:Arial"><h2>مصادقة تعديل حساب مدير النظام</h2><p>الأدمن الحالي: <b>${safeText(user.username)}</b></p><p>رمز المصادقة: <b style="font-size:24px;letter-spacing:4px">${code}</b></p><p>الرمز صالح لمدة 10 دقائق ويستخدم مرة واحدة.</p></div>`);
      await pool.query("UPDATE assetspro_otps SET used_at=NOW() WHERE user_id=$1 AND purpose='admin-change' AND used_at IS NULL", [user.id]);
      await pool.query("INSERT INTO assetspro_otps(user_id,purpose,code_hash,expires_at) VALUES($1,'admin-change',$2,$3)", [user.id, sha256(code), new Date(Date.now()+OTP_MS)]);
      await audit(req,'admin_otp_sent',true,{userId:user.id,username:user.username});
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
    if(!name || name.length > 160 || username.length < 3 || username.length > 80 || !validEmail(email) || email.length > 254 || (!id && !validPassword(password)) || (password && !validPassword(password))){
      return res.status(400).json({ok:false,message:'أكمل البيانات الصحيحة. كلمة المرور الجديدة يجب أن تكون من 12 حرفًا على الأقل وتحتوي على حرف ورقم.'});
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
      await audit(req,existing?'user_updated':'user_created',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username,details:{targetId:saved.rows[0].id,targetRole:role}});
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
      await audit(req,'user_deleted',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username,details:{targetId:Number(req.params.id),targetUsername:target.rows[0].username}});
      res.json({ok:true});
    }catch(error){next(error)}
  });

  app.post('/api/auth/recovery/request', dbRequired, async(req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    if(!validEmail(email))return res.status(400).json({ok:false,message:'أدخل بريدًا إلكترونيًا صحيحًا.'});
    if(!rateLimit(`recovery:${req.ip}:${email}`,15*60*1000,5) || !rateLimit(`recovery-ip:${req.ip}`,15*60*1000,15))return res.status(429).json({ok:false,message:'تم تجاوز عدد طلبات الاستعادة. حاول لاحقًا.'});
    try{
      const found = await pool.query("SELECT * FROM assetspro_users WHERE email_key=$1 AND status='Active'", [email]);
      const user = found.rows[0];
      if(user){
        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        await sendEmail(user.email, 'Assets Pro — استعادة بيانات الدخول', `<div dir="rtl" style="font-family:Arial"><h2>استعادة بيانات الدخول</h2><p>اسم المستخدم: <b>${safeText(user.username)}</b></p><p>رمز التحقق: <b style="font-size:24px;letter-spacing:4px">${code}</b></p><p>صالح لمدة 10 دقائق.</p></div>`);
        await pool.query("UPDATE assetspro_otps SET used_at=NOW() WHERE user_id=$1 AND purpose='password-reset' AND used_at IS NULL", [user.id]);
        await pool.query("INSERT INTO assetspro_otps(user_id,purpose,code_hash,expires_at) VALUES($1,'password-reset',$2,$3)", [user.id, sha256(code), new Date(Date.now()+OTP_MS)]);
      }
      await audit(req,'recovery_requested',true,{userId:user?.id||null,username:user?.username||'',details:{accountFound:!!user}});
      res.json({ok:true,message:'إذا كان البريد مسجلًا فستصل رسالة الاستعادة.'});
    }catch(error){next(error)}
  });

  app.post('/api/auth/recovery/reset', dbRequired, async(req, res, next) => {
    const username = normalizeUsername(req.body?.username).toLowerCase();
    const code = String(req.body?.code || '');
    const password = String(req.body?.password || '');
    if(!username || username.length > 80 || code.length < 6 || code.length > 128 || !validPassword(password))return res.status(400).json({ok:false,message:'تحقق من البيانات. كلمة المرور الجديدة يجب أن تكون من 12 حرفًا على الأقل وتحتوي على حرف ورقم.'});
    if(!rateLimit(`recovery-reset:${req.ip}:${username}`,15*60*1000,10))return res.status(429).json({ok:false,message:'تم تجاوز محاولات الاستعادة. حاول لاحقًا.'});
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
      if(!user || !valid){await client.query('COMMIT');await audit(req,'recovery_failed',false,{userId:user?.id||null,username});return res.status(403).json({ok:false,message:'رمز الاستعادة أو رمز البريد غير صحيح أو انتهت صلاحيته.'})}
      await client.query("UPDATE assetspro_users SET password_hash=$1,status='Active',failed_login_attempts=0,last_failed_login=NULL,login_locked_until=NULL,updated_at=NOW() WHERE id=$2", [await hashPassword(password), user.id]);
      await client.query('DELETE FROM assetspro_sessions WHERE user_id=$1', [user.id]);
      await client.query('COMMIT');
      await audit(req,'password_reset',true,{userId:user.id,username:user.username});
      res.json({ok:true});
    }catch(error){await client.query('ROLLBACK').catch(() => {});next(error)}finally{client.release()}
  });

  app.post('/api/auth/recovery-code', admin, async(req, res, next) => {
    const password = String(req.body?.password || '');
    const recoveryCode = String(req.body?.recoveryCode || '');
    if(!validPassword(recoveryCode))return res.status(400).json({ok:false,message:'رمز الاستعادة يجب ألا يقل عن 12 حرفًا ويحتوي على حرف ورقم.'});
    try{
      if(!await verifyPassword(password, req.assetsProUser.password_hash))return res.status(401).json({ok:false,message:'كلمة مرور الأدمن غير صحيحة.'});
      await pool.query(`INSERT INTO assetspro_auth_settings(key,value) VALUES('recovery_hash',$1)
        ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`, [await hashPassword(recoveryCode)]);
      await audit(req,'recovery_code_changed',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username});
      res.json({ok:true});
    }catch(error){next(error)}
  });

  app.post('/api/security/devices/enrollment-token', admin, async(req,res,next) => {
    try{
      const token=crypto.randomBytes(24).toString('base64url');
      const expiresAt=new Date(Date.now()+30*60*1000);
      await pool.query('DELETE FROM assetspro_device_enrollment_tokens WHERE expires_at<=NOW() OR used_at IS NOT NULL');
      await pool.query('INSERT INTO assetspro_device_enrollment_tokens(token_hash,created_by,expires_at) VALUES($1,$2,$3)',[sha256(token),req.assetsProUser.id,expiresAt]);
      await audit(req,'device_enrollment_created',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username});
      res.json({ok:true,token,expiresAt:expiresAt.toISOString()});
    }catch(error){next(error)}
  });

  app.post('/api/agent/enroll', dbRequired, async(req,res,next) => {
    if(!rateLimit(`device-enroll:${req.ip}`,15*60*1000,20))return res.status(429).json({ok:false,message:'تم تجاوز محاولات ربط الأجهزة. حاول لاحقًا.'});
    const token=String(req.body?.enrollmentToken||'').trim();
    const deviceId=String(req.body?.deviceId||'').trim();
    const deviceName=safeText(req.body?.deviceName).trim().slice(0,120);
    const osVersion=safeText(req.body?.osVersion).trim().slice(0,160);
    const agentVersion=safeText(req.body?.agentVersion).trim().slice(0,40);
    if(token.length<24||token.length>128||!validDeviceId(deviceId)||!deviceName)return res.status(400).json({ok:false,message:'بيانات ربط جهاز ويندوز غير مكتملة.'});
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const found=await client.query('SELECT * FROM assetspro_device_enrollment_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE',[sha256(token)]);
      if(!found.rows[0]){await client.query('ROLLBACK');await audit(req,'device_enrollment_failed',false,{details:{deviceId}});return res.status(403).json({ok:false,message:'رمز ربط الجهاز غير صحيح أو انتهت صلاحيته.'})}
      const deviceSecret=crypto.randomBytes(32).toString('base64url');
      await client.query(`INSERT INTO assetspro_devices(device_id,secret_hash,device_name,os_version,agent_version,last_ip,last_seen)
        VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(device_id) DO UPDATE SET secret_hash=EXCLUDED.secret_hash,device_name=EXCLUDED.device_name,
        os_version=EXCLUDED.os_version,agent_version=EXCLUDED.agent_version,last_ip=EXCLUDED.last_ip,last_seen=NOW(),updated_at=NOW()`,
        [deviceId,sha256(deviceSecret),deviceName,osVersion,agentVersion,String(req.ip||'').slice(0,80)]);
      await client.query('UPDATE assetspro_device_enrollment_tokens SET used_at=NOW() WHERE token_hash=$1',[sha256(token)]);
      await client.query('COMMIT');
      await audit(req,'device_enrolled',true,{details:{deviceId,deviceName}});
      res.status(201).json({ok:true,deviceSecret,heartbeatMinutes:5});
    }catch(error){await client.query('ROLLBACK').catch(()=>{});next(error)}finally{client.release()}
  });

  app.post('/api/agent/heartbeat', deviceRequired, async(req,res,next) => {
    try{
      const value=req.body||{};
      const defenderEnabled=!!value.defenderEnabled,realtimeEnabled=!!value.realtimeEnabled,firewallEnabled=!!value.firewallEnabled;
      const tamperProtected=!!value.tamperProtected,rdpEnabled=!!value.rdpEnabled;
      const signatureAgeDays=boundedInteger(value.signatureAgeDays,0,999,999),failedLogons24h=boundedInteger(value.failedLogons24h,0,100000,0);
      const allowedBitlocker=new Set(['on','off','unknown','suspended','not-supported']);
      const bitlockerStatus=allowedBitlocker.has(value.bitlockerStatus)?value.bitlockerStatus:'unknown';
      const alerts=Array.isArray(value.alerts)?value.alerts.slice(0,20).map(x=>safeText(x).trim().slice(0,200)).filter(Boolean):[];
      let riskScore=0;
      if(!defenderEnabled)riskScore+=35;if(!realtimeEnabled)riskScore+=25;if(!firewallEnabled)riskScore+=20;
      if(signatureAgeDays>3)riskScore+=10;if(!tamperProtected)riskScore+=5;if(!['on','not-supported'].includes(bitlockerStatus))riskScore+=5;
      if(failedLogons24h>=10)riskScore+=10;if(rdpEnabled)riskScore+=5;if(alerts.length)riskScore+=Math.min(20,alerts.length*5);
      riskScore=Math.min(100,riskScore);
      const previousRisk=Number(req.assetsProDevice.risk_score||0);
      const result=await pool.query(`UPDATE assetspro_devices SET device_name=$1,os_version=$2,agent_version=$3,defender_enabled=$4,realtime_enabled=$5,
        firewall_enabled=$6,bitlocker_status=$7,tamper_protected=$8,signature_age_days=$9,failed_logons_24h=$10,rdp_enabled=$11,
        risk_score=$12,alerts=$13::jsonb,last_ip=$14,last_seen=NOW(),updated_at=NOW() WHERE device_id=$15 RETURNING *`,[
        safeText(value.deviceName||req.assetsProDevice.device_name).trim().slice(0,120),safeText(value.osVersion||req.assetsProDevice.os_version).trim().slice(0,160),
        safeText(value.agentVersion||req.assetsProDevice.agent_version).trim().slice(0,40),defenderEnabled,realtimeEnabled,firewallEnabled,bitlockerStatus,
        tamperProtected,signatureAgeDays,failedLogons24h,rdpEnabled,riskScore,JSON.stringify(alerts),String(req.ip||'').slice(0,80),req.assetsProDevice.device_id
      ]);
      if(riskScore>=50&&(previousRisk<50||alerts.length))await audit(req,'windows_device_alert',false,{details:{deviceId:req.assetsProDevice.device_id,riskScore,alerts}});
      res.json({ok:true,device:publicDevice(result.rows[0]),nextHeartbeatMinutes:5});
    }catch(error){next(error)}
  });

  app.get('/api/security/devices', admin, async(req,res,next) => {
    try{
      const result=await pool.query('SELECT * FROM assetspro_devices ORDER BY risk_score DESC,last_seen DESC');
      res.json({ok:true,devices:result.rows.map(publicDevice)});
    }catch(error){next(error)}
  });

  app.delete('/api/security/devices/:deviceId', admin, async(req,res,next) => {
    const deviceId=String(req.params.deviceId||'');
    if(!validDeviceId(deviceId))return res.status(400).json({ok:false,message:'معرف الجهاز غير صالح.'});
    try{
      const removed=await pool.query('DELETE FROM assetspro_devices WHERE device_id=$1 RETURNING device_name',[deviceId]);
      if(!removed.rows[0])return res.status(404).json({ok:false,message:'الجهاز غير موجود.'});
      await audit(req,'device_revoked',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username,details:{deviceId,deviceName:removed.rows[0].device_name}});
      res.json({ok:true});
    }catch(error){next(error)}
  });

  app.get('/api/security/summary', admin, async(req, res, next) => {
    try{
      const [events,sessions,locked,devices] = await Promise.all([
        pool.query(`SELECT
          COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '24 hours')::int AS events_24h,
          COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '24 hours' AND success=FALSE)::int AS blocked_24h,
          COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '24 hours' AND event_type='login_success')::int AS logins_24h
          FROM assetspro_security_events`),
        pool.query('SELECT COUNT(*)::int AS count FROM assetspro_sessions WHERE expires_at>NOW()'),
        pool.query('SELECT COUNT(*)::int AS count FROM assetspro_users WHERE login_locked_until>NOW()'),
        pool.query(`SELECT COUNT(*) FILTER (WHERE last_seen>NOW()-INTERVAL '15 minutes')::int AS online,
          COUNT(*) FILTER (WHERE risk_score>=50)::int AS critical FROM assetspro_devices`)
      ]);
      res.json({ok:true,events24h:events.rows[0].events_24h,blocked24h:events.rows[0].blocked_24h,logins24h:events.rows[0].logins_24h,activeSessions:sessions.rows[0].count,lockedUsers:locked.rows[0].count,devicesOnline:devices.rows[0].online,criticalDevices:devices.rows[0].critical,retentionDays:90});
    }catch(error){next(error)}
  });

  app.get('/api/security/events', admin, async(req, res, next) => {
    try{
      const limit = Math.min(200,Math.max(1,Number(req.query.limit||100)));
      const result = await pool.query(`SELECT e.id,e.event_type,e.success,e.username_key,e.ip_address,e.request_id,e.details,e.created_at,u.name AS user_name
        FROM assetspro_security_events e LEFT JOIN assetspro_users u ON u.id=e.user_id
        ORDER BY e.created_at DESC LIMIT $1`,[limit]);
      res.json({ok:true,events:result.rows.map(row=>({...row,created_at:new Date(row.created_at).toISOString()}))});
    }catch(error){next(error)}
  });

  app.post('/api/security/sessions/revoke-others', admin, async(req, res, next) => {
    try{
      const currentTokenHash = sha256(cookieValue(req,sessionCookieName()));
      const result = await pool.query('DELETE FROM assetspro_sessions WHERE token_hash<>$1',[currentTokenHash]);
      await audit(req,'sessions_revoked',true,{userId:req.assetsProUser.id,username:req.assetsProUser.username,details:{revoked:result.rowCount}});
      res.json({ok:true,revoked:result.rowCount});
    }catch(error){next(error)}
  });

  return {configured, required, admin, requirePage, sessionUser, publicUser, audit};
}

module.exports = {createCentralAuth};
