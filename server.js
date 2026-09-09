
const express = require('express');
const fs = require('fs');
const path = require('path');
const {createCentralAuth} = require('./central-auth');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA = __dirname;
const MASTER = path.join(DATA,'Assets_Master_Data.json');
const INVENTORY = path.join(DATA,'inventory.json');
const JOURNALS = path.join(DATA,'journals.json');
const HR_MONTHS = path.join(DATA,'hr_months.json');

app.use(express.json({limit:'25mb'}));
app.use(express.static(__dirname,{
  setHeaders(res,file){
    if(file.endsWith('.html')){
      res.setHeader('Cache-Control','no-store');
      res.setHeader('Permissions-Policy','camera=(self)');
    }
  }
}));

async function start(){
const auth = await createCentralAuth(app);

function readJSON(file,fallback){
  try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch(e){return fallback}
}
function writeJSON(file,data){
  const temp=file+'.tmp';
  fs.writeFileSync(temp,JSON.stringify(data,null,2),'utf8');
  fs.renameSync(temp,file);
}
function backup(file,prefix){
  if(!fs.existsSync(file))return;
  const dir=path.join(DATA,'backups');
  fs.mkdirSync(dir,{recursive:true});
  const stamp=new Date().toISOString().replace(/[:.]/g,'-');
  fs.copyFileSync(file,path.join(dir,`${prefix}_${stamp}.json`));
  const files=fs.readdirSync(dir).filter(x=>x.startsWith(prefix+'_')).sort().reverse();
  files.slice(20).forEach(f=>{try{fs.unlinkSync(path.join(dir,f))}catch(e){}});
}

app.get('/api/health',(req,res)=>res.json({ok:true,app:'Assets Pro',version:'3.7.0',centralAuth:auth.configured,time:new Date().toISOString()}));

app.get('/api/master-data',(req,res)=>{
  res.json(readJSON(MASTER,{schema:'assets-pro-master-data-v1',assets:[]}));
});

app.put('/api/master-data',auth.requirePage('masterdata'),(req,res)=>{
  const body=req.body||{};
  if(body.schema!=='assets-pro-master-data-v1' || !Array.isArray(body.assets)){
    return res.status(400).send('Invalid master data payload');
  }
  backup(MASTER,'master');
  body.updatedAt=new Date().toISOString();
  writeJSON(MASTER,body);
  res.json({ok:true,assetCount:body.assets.length,updatedAt:body.updatedAt});
});

app.get('/api/inventory',(req,res)=>{
  res.json(readJSON(INVENTORY,{sessions:[],records:[]}));
});

app.post('/api/inventory/sync',auth.requirePage('inventorybarcode'),(req,res)=>{
  const body=req.body||{};
  if(!Array.isArray(body.sessions)||!Array.isArray(body.records)){
    return res.status(400).send('Invalid inventory payload');
  }
  backup(INVENTORY,'inventory');
  body.updatedAt=new Date().toISOString();
  writeJSON(INVENTORY,body);
  res.json({ok:true,updatedAt:body.updatedAt});
});

app.get('/api/backups',(req,res)=>{
  const dir=path.join(DATA,'backups');
  if(!fs.existsSync(dir))return res.json([]);
  res.json(fs.readdirSync(dir).sort().reverse());
});

app.get('/api/journals',(req,res)=>{
  res.json(readJSON(JOURNALS,{journals:[],savedAt:''}));
});

app.post('/api/journals',auth.requirePage('journals'),(req,res)=>{
  const body=req.body||{};
  if(!Array.isArray(body.journals))return res.status(400).send('Invalid journals payload');
  backup(JOURNALS,'journals');
  const payload={journals:body.journals,savedAt:new Date().toISOString()};
  writeJSON(JOURNALS,payload);
  res.json({ok:true,count:payload.journals.length,savedAt:payload.savedAt});
});

app.post('/api/backup-assets',auth.admin,(req,res)=>{
  const body=req.body||{};
  const dir=path.join(DATA,'backups');fs.mkdirSync(dir,{recursive:true});
  const stamp=new Date().toISOString().replace(/[:.]/g,'-');
  const name=`assets_manual_${stamp}.json`,target=path.join(dir,name);
  writeJSON(target,body);
  res.json({ok:true,savedAt:new Date().toISOString(),relativePath:path.join('backups',name)});
});

app.post('/api/backup-complete',auth.admin,(req,res)=>{
  const body=req.body||{};
  if(body.app!=='Assets Pro'||body.schema!=='assets-pro-complete-backup-v3')return res.status(400).json({ok:false,message:'Invalid backup payload'});
  const dir=path.join(DATA,'backups','complete');fs.mkdirSync(dir,{recursive:true});
  const stamp=new Date().toISOString().replace(/[:.]/g,'-'),name=`AssetsPro_Complete_${stamp}.json`,target=path.join(dir,name);
  writeJSON(target,body);
  const files=fs.readdirSync(dir).filter(x=>x.endsWith('.json')).sort().reverse();files.slice(30).forEach(f=>{try{fs.unlinkSync(path.join(dir,f))}catch(e){}});
  res.json({ok:true,savedAt:new Date().toISOString(),relativePath:path.join('backups','complete',name)});
});

app.post('/api/recovery-email',(req,res)=>res.status(410).json({ok:false,message:'تم نقل استعادة كلمة المرور إلى نظام المصادقة المركزي.'}));
app.post('/api/admin-approval-email',(req,res)=>res.status(410).json({ok:false,message:'تم نقل مصادقة الأدمن إلى نظام المصادقة المركزي.'}));

app.post('/api/hr/save-month',auth.requirePage('hrlink'),(req,res)=>{
  const body=req.body||{};
  if(!body.period)return res.status(400).send('Period is required');
  const data=readJSON(HR_MONTHS,{months:[]});
  data.months=Array.isArray(data.months)?data.months:[];
  data.months=data.months.filter(x=>x.period!==body.period);
  data.months.unshift({...body,savedAt:new Date().toISOString()});
  data.updatedAt=new Date().toISOString();
  backup(HR_MONTHS,'hr_months');writeJSON(HR_MONTHS,data);
  res.json({ok:true,json:'hr_months.json',period:body.period,savedAt:data.updatedAt});
});

app.post('/api/export-journals',auth.requirePage('journals'),(req,res)=>{
  const journals=Array.isArray(req.body?.journals)?req.body.journals:[];
  if(!journals.length)return res.status(400).send('No journals');
  const esc=v=>String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const rows=journals.flatMap(j=>(j.lines||[]).map(x=>`<tr><td>${esc(j.period)}</td><td>${esc(x.costCenter)}</td><td>${esc(x.accountCode)}</td><td>${esc(x.accountName)}</td><td>${esc(x.description)}</td><td>${Number(x.debit||0)}</td><td>${Number(x.credit||0)}</td><td>${esc(j.status)}</td></tr>`)).join('');
  const html=`<html dir="rtl"><head><meta charset="UTF-8"></head><body><table border="1"><tr><th>الفترة</th><th>مركز التكلفة</th><th>رقم الحساب</th><th>اسم الحساب</th><th>البيان</th><th>مدين</th><th>دائن</th><th>الحالة</th></tr>${rows}</table></body></html>`;
  res.setHeader('Content-Type','application/vnd.ms-excel; charset=utf-8');
  res.setHeader('Content-Disposition',"attachment; filename*=UTF-8''AssetsPro_Journals.xls");
  res.send('\ufeff'+html);
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));

app.use((error,req,res,next)=>{
  console.error('Unhandled server error:',error.message);
  res.status(500).json({ok:false,message:'حدث خطأ غير متوقع في الخادم.'});
});

app.listen(PORT,'0.0.0.0',()=>console.log(`Assets Pro v3.7.0 running on port ${PORT}`));
}

start().catch(error=>{
  console.error('Assets Pro failed to start:',error);
  process.exitCode=1;
});
