'use strict';

const crypto = require('crypto');

const windows = new Map();
const MAX_TRACKED_CLIENTS = 10000;

function clientKey(req, scope){
  return `${scope}:${req.ip || req.socket?.remoteAddress || 'unknown'}`;
}

function pruneWindows(now){
  if(windows.size <= MAX_TRACKED_CLIENTS)return;
  for(const [key, value] of windows){
    if(value.resetAt <= now)windows.delete(key);
    if(windows.size <= Math.floor(MAX_TRACKED_CLIENTS * 0.8))break;
  }
}

function limiter({scope, limit, windowMs}){
  return (req, res, next) => {
    const now = Date.now();
    pruneWindows(now);
    const key = clientKey(req, scope);
    let entry = windows.get(key);
    if(!entry || entry.resetAt <= now)entry = {count:0, resetAt:now + windowMs};
    entry.count += 1;
    windows.set(key, entry);
    const remaining = Math.max(0, limit - entry.count);
    res.setHeader('RateLimit-Limit', String(limit));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));
    if(entry.count > limit){
      const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ok:false,message:'تم تجاوز عدد الطلبات المسموح. حاول مرة أخرى لاحقًا.'});
    }
    next();
  };
}

function sameOriginOnly(req, res, next){
  if(!['POST','PUT','PATCH','DELETE'].includes(req.method))return next();
  const fetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if(fetchSite === 'cross-site')return res.status(403).json({ok:false,message:'تم رفض طلب قادم من موقع خارجي.'});
  const origin = req.headers.origin;
  if(!origin)return next();
  try{
    const originUrl = new URL(origin);
    const expectedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
    if(originUrl.host !== expectedHost)return res.status(403).json({ok:false,message:'مصدر الطلب غير مسموح.'});
    return next();
  }catch(_){
    return res.status(403).json({ok:false,message:'مصدر الطلب غير صالح.'});
  }
}

function requireJson(req, res, next){
  if(!['POST','PUT','PATCH'].includes(req.method))return next();
  if(!req.is('application/json'))return res.status(415).json({ok:false,message:'يجب إرسال الطلب بصيغة JSON.'});
  next();
}

function securityHeaders(req, res, next){
  const requestId = crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.sheetjs.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https://api.qrserver.com",
    "connect-src 'self'",
    "worker-src 'self' blob:"
  ].join('; '));
  if(process.env.NODE_ENV === 'production')res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if(req.path.startsWith('/api/'))res.setHeader('Cache-Control', 'no-store, max-age=0');
  next();
}

function installSecurity(app){
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use('/api', limiter({scope:'api',limit:600,windowMs:15 * 60 * 1000}));
  app.use('/api/auth', limiter({scope:'auth',limit:80,windowMs:15 * 60 * 1000}));
  app.use('/api', sameOriginOnly, requireJson);
}

module.exports = {installSecurity, limiter, sameOriginOnly, requireJson, securityHeaders};
