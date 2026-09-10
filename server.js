'use strict';

const express=require('express');
const fs=require('fs');
const path=require('path');
const {createCentralAuth}=require('./central-auth');
const {createCentralStore}=require('./central-store');
const {installSecurity}=require('./security');
const {STATE_PARTITIONS,partitionForKey,canPartition,canKey}=require('./state-policy');

const app=express();
const PORT=process.env.PORT||3000;
const DATA=__dirname;
const FILES={
  master:path.join(DATA,'Assets_Master_Data.json'),
  inventory:path.join(DATA,'inventory.json'),
  journals:path.join(DATA,'journals.json'),
  hr:path.join(DATA,'hr_months.json')
};

installSecurity(app);
app.use(express.json({limit:'25mb',strict:true}));
app.use('/api',(req,res,next)=>{
  if(!req.body||typeof req.body!=='object')return next();
  let nodes=0,unsafe=false;
  const visit=(value,depth=0)=>{
    if(unsafe||depth>40||++nodes>250000){unsafe=true;return}
    if(!value||typeof value!=='object')return;
    for(const key of Object.keys(value)){
      if(key==='__proto__'||key==='prototype'||key==='constructor'){unsafe=true;return}
      visit(value[key],depth+1);
    }
  };
  visit(req.body);
  if(unsafe)return res.status(400).json({ok:false,message:'تركيب بيانات الطلب غير مسموح.'});
  next();
});
app.use((req,res,next)=>{
  if(req.path.startsWith('/api/'))return next();
  if(/\.(?:js|json|lock|ya?ml|txt|xlsx|zip)$/i.test(req.path))return res.status(404).end();
  if(/\.html$/i.test(req.path)&&!['/index.html','/hr.html'].includes(req.path))return res.status(404).end();
  next();
});

function readJSON(file,fallback){
  try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch(_){return fallback}
}
function decorate(doc){
  return {...doc.payload,_serverVersion:doc.version,_checksum:doc.checksum,_updatedAt:doc.updatedAt};
}
function context(req,reason){
  return {userId:req.assetsProUser?.id||null,username:req.assetsProUser?.username||'',ip:req.ip,reason:String(reason||'تحديث مركزي').slice(0,300)};
}
function expected(body){
  const value=Number(body?._serverVersion);
  return Number.isInteger(value)&&value>0?value:null;
}

async function start(){
  const auth=await createCentralAuth(app);
  let store=null;
  if(auth.pool){
    store=createCentralStore(auth.pool);
    await store.init();
    await store.seed('master-data',readJSON(FILES.master,{schema:'assets-pro-master-data-v1',assets:[]}));
    await store.seed('inventory',readJSON(FILES.inventory,{sessions:[],records:[]}));
    await store.seed('journals',readJSON(FILES.journals,{journals:[],savedAt:''}));
    await store.seed('hr-months',readJSON(FILES.hr,{months:[]}));
    for(const partition of Object.keys(STATE_PARTITIONS))await store.seed(`state-${partition}`,{storage:{}});
    console.log('Assets Pro protected central data store is ready');
  }
  const needStore=(req,res,next)=>store?next():res.status(503).json({ok:false,message:'مخزن البيانات المركزي غير متاح.'});

  app.get('/api/health',(req,res)=>res.json({ok:true,app:'Assets Pro',version:'3.9.0',centralAuth:auth.configured,centralData:!!store,time:new Date().toISOString()}));

  app.get('/api/master-data',auth.required,needStore,async(req,res,next)=>{
    try{res.json(decorate(await store.read('master-data')))}catch(error){next(error)}
  });
  app.put('/api/master-data',auth.requireAnyPage(['assets','masterdata']),needStore,async(req,res,next)=>{
    const body=req.body||{};
    if(body.schema!=='assets-pro-master-data-v1'||!Array.isArray(body.assets)||body.assets.length>100000)return res.status(400).json({ok:false,message:'بيانات الأصول غير صالحة.'});
    try{
      const saved=await store.write('master-data',{...body,updatedAt:new Date().toISOString()},{...context(req,body.reason),expectedVersion:expected(body)});
      res.json({ok:true,assetCount:body.assets.length,updatedAt:saved.updatedAt,version:saved.version,checksum:saved.checksum});
    }catch(error){next(error)}
  });

  app.get('/api/inventory',auth.requirePage('inventorybarcode'),needStore,async(req,res,next)=>{
    try{res.json(decorate(await store.read('inventory')))}catch(error){next(error)}
  });
  app.post('/api/inventory/sync',auth.requirePage('inventorybarcode'),needStore,async(req,res,next)=>{
    const body=req.body||{};
    if(!Array.isArray(body.sessions)||!Array.isArray(body.records))return res.status(400).json({ok:false,message:'بيانات الجرد غير صالحة.'});
    try{
      const allowedKeys=new Set(['assetsProInventoryCyclesV220','assetsProInventoryCyclesV220:active','assetsProInventoryActionsV240','assetsProInventorySessions','assetsProInventoryRecords','assetsProActiveInventorySession']),state={};
      if(body.state&&typeof body.state==='object')for(const [key,value] of Object.entries(body.state))if(allowedKeys.has(key)&&(value===null||typeof value==='string'))state[key]=value;
      const saved=await store.write('inventory',{sessions:body.sessions,records:body.records,state,updatedAt:new Date().toISOString()},{...context(req,'مزامنة الجرد'),expectedVersion:expected(body)});
      res.json({ok:true,updatedAt:saved.updatedAt,version:saved.version,checksum:saved.checksum});
    }catch(error){next(error)}
  });

  app.get('/api/journals',auth.requirePage('journals'),needStore,async(req,res,next)=>{
    try{res.json(decorate(await store.read('journals')))}catch(error){next(error)}
  });
  app.post('/api/journals',auth.requirePage('journals'),needStore,async(req,res,next)=>{
    const body=req.body||{};
    if(!Array.isArray(body.journals)||body.journals.length>100000)return res.status(400).json({ok:false,message:'بيانات القيود غير صالحة.'});
    try{
      const payload={journals:body.journals,savedAt:new Date().toISOString()};
      const saved=await store.write('journals',payload,{...context(req,'حفظ القيود المحاسبية'),expectedVersion:expected(body)});
      res.json({ok:true,count:payload.journals.length,savedAt:payload.savedAt,version:saved.version,checksum:saved.checksum});
    }catch(error){next(error)}
  });

  app.get('/api/hr/months',auth.requirePage('hrlink'),needStore,async(req,res,next)=>{
    try{res.json(decorate(await store.read('hr-months')))}catch(error){next(error)}
  });
  app.post('/api/hr/save-month',auth.requirePage('hrlink'),needStore,async(req,res,next)=>{
    const body=req.body||{};
    if(!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(body.period||'')))return res.status(400).json({ok:false,message:'الفترة غير صالحة.'});
    try{
      const current=await store.read('hr-months'),months=Array.isArray(current.payload?.months)?current.payload.months:[];
      const nextMonths=[{...body,savedAt:new Date().toISOString()},...months.filter(x=>x.period!==body.period)].slice(0,240);
      const saved=await store.write('hr-months',{months:nextMonths,updatedAt:new Date().toISOString()},{...context(req,`حفظ رواتب ${body.period}`),expectedVersion:current.version});
      res.json({ok:true,storage:'postgresql',period:body.period,savedAt:saved.updatedAt,version:saved.version});
    }catch(error){next(error)}
  });

  app.post('/api/backup-assets',auth.admin,needStore,async(req,res,next)=>{
    try{
      const current=await store.read('manual-assets-backup');
      const saved=await store.write('manual-assets-backup',req.body||{},{...context(req,'نسخة احتياطية يدوية للأصول'),expectedVersion:current?.version});
      res.json({ok:true,savedAt:saved.updatedAt,storage:'postgresql',version:saved.version});
    }catch(error){next(error)}
  });
  app.post('/api/backup-complete',auth.admin,needStore,async(req,res,next)=>{
    const body=req.body||{};
    if(body.app!=='Assets Pro'||body.schema!=='assets-pro-complete-backup-v3')return res.status(400).json({ok:false,message:'ملف النسخة الاحتياطية غير صالح.'});
    try{
      const current=await store.read('complete-backup');
      const saved=await store.write('complete-backup',body,{...context(req,'نسخة احتياطية كاملة'),expectedVersion:current?.version});
      res.json({ok:true,savedAt:saved.updatedAt,storage:'postgresql',version:saved.version});
    }catch(error){next(error)}
  });
  app.get('/api/backups',auth.admin,needStore,async(req,res,next)=>{
    try{res.json({ok:true,master:await store.versions('master-data'),inventory:await store.versions('inventory'),journals:await store.versions('journals'),complete:await store.versions('complete-backup')})}catch(error){next(error)}
  });
  app.get('/api/audit-log',auth.admin,needStore,async(req,res,next)=>{
    try{res.json({ok:true,events:await store.audit(req.query.limit)})}catch(error){next(error)}
  });
  app.get('/api/security-events',auth.admin,async(req,res,next)=>{
    try{
      const limit=Math.max(1,Math.min(1000,Number(req.query.limit)||300));
      const result=await auth.pool.query(`SELECT id,username,event_type,success,ip_address,request_id,details,created_at
        FROM assetspro_security_events ORDER BY id DESC LIMIT $1`,[limit]);
      res.json({ok:true,events:result.rows});
    }catch(error){next(error)}
  });
  app.post('/api/data/:key/restore/:version',auth.admin,needStore,async(req,res,next)=>{
    const keys={master:'master-data',inventory:'inventory',journals:'journals',hr:'hr-months'};
    const key=keys[req.params.key];
    if(!key)return res.status(404).json({ok:false,message:'نوع البيانات غير معروف.'});
    try{
      const saved=await store.restore(key,req.params.version,context(req,`استعادة ${key}`));
      res.json({ok:true,key,version:saved.version,checksum:saved.checksum,updatedAt:saved.updatedAt});
    }catch(error){next(error)}
  });

  app.get('/api/state/:partition',auth.required,needStore,async(req,res,next)=>{
    const partition=String(req.params.partition||'');
    if(!canPartition(req.assetsProUser,partition,false))return res.status(403).json({ok:false,message:'ليس لديك صلاحية لبيانات هذا الموديول.'});
    try{const doc=await store.read(`state-${partition}`),storage={};for(const [key,value] of Object.entries(doc.payload?.storage||{}))if(canKey(req.assetsProUser,key,false))storage[key]=value;res.json({...decorate(doc),storage})}catch(error){next(error)}
  });
  app.put('/api/state/:partition',auth.required,needStore,async(req,res,next)=>{
    const partition=String(req.params.partition||''),storage=req.body?.storage;
    if(!canPartition(req.assetsProUser,partition,true))return res.status(403).json({ok:false,message:'ليس لديك صلاحية لتعديل بيانات هذا الموديول.'});
    if(!storage||typeof storage!=='object'||Array.isArray(storage)||Object.keys(storage).length>500)return res.status(400).json({ok:false,message:'بيانات الموديول غير صالحة.'});
    const clean={};let total=0;
    for(const [key,value] of Object.entries(storage)){
      if(partitionForKey(key)!==partition||!canKey(req.assetsProUser,key,true)||typeof value!=='string')return res.status(403).json({ok:false,message:'توجد مفاتيح بيانات غير مصرح لك بتعديلها.'});
      total+=Buffer.byteLength(value);if(total>12*1024*1024)return res.status(413).json({ok:false,message:'حجم بيانات الموديول أكبر من الحد المسموح.'});
      clean[key]=value;
    }
    try{
      const current=await store.read(`state-${partition}`);
      if(!current.payload?.initialized&&req.assetsProUser.role!=='Admin')return res.status(403).json({ok:false,message:'يلزم أن يفتح مدير النظام النسخة الجديدة أولًا لتهيئة البيانات المركزية.'});
      const merged={...(current.payload?.storage||{})};
      for(const key of Object.keys(merged))if(canKey(req.assetsProUser,key,true))delete merged[key];
      Object.assign(merged,clean);
      const saved=await store.write(`state-${partition}`,{storage:merged,initialized:true},{...context(req,`مزامنة ${partition}`),expectedVersion:expected(req.body)});
      res.json({ok:true,partition,version:saved.version,checksum:saved.checksum,updatedAt:saved.updatedAt});
    }catch(error){next(error)}
  });

  app.get('/api/attachments/:asset/:type/meta',auth.requireAnyPage(['assets','masterdata']),needStore,async(req,res,next)=>{
    try{const row=await store.getAttachment(String(req.params.asset).slice(0,100),String(req.params.type),true);if(!row)return res.status(404).json({ok:false,message:'المرفق غير موجود.'});res.json({ok:true,name:row.file_name,mime:row.mime_type,size:Number(row.file_size),checksum:row.checksum,updatedAt:row.updated_at})}catch(error){next(error)}
  });
  app.get('/api/attachments/:asset/:type',auth.requireAnyPage(['assets','masterdata']),needStore,async(req,res,next)=>{
    try{const row=await store.getAttachment(String(req.params.asset).slice(0,100),String(req.params.type));if(!row)return res.status(404).json({ok:false,message:'المرفق غير موجود.'});res.setHeader('Content-Type',row.mime_type);res.setHeader('Content-Length',String(row.file_size));res.setHeader('X-Content-SHA256',row.checksum);const disposition=row.mime_type.startsWith('image/')?'inline':'attachment';res.setHeader('Content-Disposition',`${disposition}; filename*=UTF-8''${encodeURIComponent(row.file_name)}`);res.send(row.content)}catch(error){next(error)}
  });
  app.post('/api/attachments/:asset/:type',auth.requireAnyPage(['assets','masterdata']),needStore,async(req,res,next)=>{
    if(req.assetsProUser.role==='Viewer')return res.status(403).json({ok:false,message:'المستخدم للعرض فقط.'});
    const asset=String(req.params.asset||'').trim().slice(0,100),type=String(req.params.type||'');
    if(!asset||!['photo','invoice','contract','warranty','other'].includes(type))return res.status(400).json({ok:false,message:'بيانات المرفق غير صالحة.'});
    const name=String(req.body?.name||'').replace(/[\r\n\\/]/g,'_').slice(0,200),mime=String(req.body?.mime||'application/octet-stream').slice(0,100),raw=String(req.body?.dataBase64||'');
    const allowedMimes=new Set(['image/jpeg','image/png','image/webp','application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/octet-stream']);
    if(!allowedMimes.has(mime)||(type==='photo'&&!mime.startsWith('image/')))return res.status(415).json({ok:false,message:'نوع الملف غير مسموح. استخدم JPG أو PNG أو WEBP أو PDF أو Word.'});
    if(!name||!raw||!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))return res.status(400).json({ok:false,message:'محتوى المرفق غير صالح.'});
    const content=Buffer.from(raw,'base64');if(!content.length||content.length>10*1024*1024)return res.status(413).json({ok:false,message:'الحد الأقصى للمرفق المركزي 10 MB.'});
    try{const row=await store.putAttachment(asset,type,{name,mime,content},context(req,'حفظ مرفق'));res.json({ok:true,name:row.file_name,mime:row.mime_type,size:Number(row.file_size),checksum:row.checksum,updatedAt:row.updated_at})}catch(error){next(error)}
  });
  app.delete('/api/attachments/:asset/:type',auth.requireAnyPage(['assets','masterdata']),needStore,async(req,res,next)=>{
    if(req.assetsProUser.role==='Viewer')return res.status(403).json({ok:false,message:'المستخدم للعرض فقط.'});
    try{const deleted=await store.deleteAttachment(String(req.params.asset).slice(0,100),String(req.params.type),context(req,'حذف مرفق'));res.status(deleted?200:404).json({ok:deleted})}catch(error){next(error)}
  });

  app.post('/api/recovery-email',(req,res)=>res.status(410).json({ok:false,message:'تم نقل استعادة كلمة المرور إلى نظام المصادقة المركزي.'}));
  app.post('/api/admin-approval-email',(req,res)=>res.status(410).json({ok:false,message:'تم نقل مصادقة الأدمن إلى نظام المصادقة المركزي.'}));

  app.post('/api/export-journals',auth.requirePage('journals'),(req,res)=>{
    const journals=Array.isArray(req.body?.journals)?req.body.journals:[];
    if(!journals.length)return res.status(400).json({ok:false,message:'لا توجد قيود للتصدير.'});
    const esc=v=>String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const rows=journals.flatMap(j=>(j.lines||[]).map(x=>`<tr><td>${esc(j.period)}</td><td>${esc(x.costCenter)}</td><td>${esc(x.accountCode)}</td><td>${esc(x.accountName)}</td><td>${esc(x.description)}</td><td>${Number(x.debit||0)}</td><td>${Number(x.credit||0)}</td><td>${esc(j.status)}</td></tr>`)).join('');
    const html=`<html dir="rtl"><head><meta charset="UTF-8"></head><body><table border="1"><tr><th>الفترة</th><th>مركز التكلفة</th><th>رقم الحساب</th><th>اسم الحساب</th><th>البيان</th><th>مدين</th><th>دائن</th><th>الحالة</th></tr>${rows}</table></body></html>`;
    res.setHeader('Content-Type','application/vnd.ms-excel; charset=utf-8');
    res.setHeader('Content-Disposition',"attachment; filename*=UTF-8''AssetsPro_Journals.xls");
    res.send('\ufeff'+html);
  });

  app.get('/hr.html',auth.requirePage('hrlink'),(req,res)=>res.sendFile(path.join(DATA,'hr.html')));
  app.use(express.static(DATA,{index:false,dotfiles:'deny',setHeaders(res,file){
    if(file.endsWith('.html'))res.setHeader('Cache-Control','no-store');
  }}));
  app.all('/api/*',(req,res)=>res.status(404).json({ok:false,message:'واجهة API المطلوبة غير موجودة.',requestId:req.requestId}));
  app.get('*',(req,res)=>res.sendFile(path.join(DATA,'index.html')));
  app.use((error,req,res,next)=>{
    console.error('Unhandled server error',req.requestId,error.code||'',error.message);
    const status=Number(error.status)||500;
    res.status(status).json({ok:false,code:error.code||'SERVER_ERROR',message:status<500?error.message:'حدث خطأ غير متوقع في الخادم.',requestId:req.requestId});
  });

  app.listen(PORT,'0.0.0.0',()=>console.log(`Assets Pro v3.9.0 full central server running on port ${PORT}`));
}

start().catch(error=>{console.error('Assets Pro failed to start:',error);process.exitCode=1});
