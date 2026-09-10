'use strict';

const crypto=require('crypto');

function installSecurity(app){
  app.disable('x-powered-by');
  app.set('trust proxy',1);
  const requests=new Map();
  const allowedOrigins=new Set(String(process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean));
  setInterval(()=>{
    const cutoff=Date.now()-10*60*1000;
    for(const [key,value] of requests)if(value.started<cutoff)requests.delete(key);
  },5*60*1000).unref();

  app.use((req,res,next)=>{
    const requestId=crypto.randomUUID();
    req.requestId=requestId;
    res.setHeader('X-Request-Id',requestId);
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy','same-origin');
    res.setHeader('Cross-Origin-Resource-Policy','same-origin');
    res.setHeader('Permissions-Policy','camera=(self), microphone=(), geolocation=(), payment=()');
    res.setHeader('Content-Security-Policy',[
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.sheetjs.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' data: https://fonts.gstatic.com",
      "img-src 'self' data: blob: https://api.qrserver.com",
      "connect-src 'self'",
      "frame-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
    ].join('; '));
    if(process.env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
    if(req.path.startsWith('/api/'))res.setHeader('Cache-Control','no-store');
    next();
  });

  app.use('/api',(req,res,next)=>{
    const now=Date.now(), key=String(req.ip||req.socket.remoteAddress||'unknown');
    let item=requests.get(key);
    if(!item||now-item.started>5*60*1000)item={started:now,count:0};
    item.count++;requests.set(key,item);
    if(item.count>600){
      res.setHeader('Retry-After','300');
      return res.status(429).json({ok:false,message:'تم تجاوز عدد الطلبات المسموح. حاول لاحقًا.'});
    }
    next();
  });

  app.use('/api',(req,res,next)=>{
    if(!['POST','PUT','PATCH','DELETE'].includes(req.method))return next();
    const origin=req.get('origin');
    if(!origin)return next();
    try{
      const url=new URL(origin),sameHost=url.host===req.get('host');
      if(sameHost||allowedOrigins.has(origin))return next();
    }catch(_){/* rejected below */}
    return res.status(403).json({ok:false,message:'تم رفض الطلب لأنه صادر من موقع غير مصرح به.'});
  });
}

module.exports={installSecurity};
