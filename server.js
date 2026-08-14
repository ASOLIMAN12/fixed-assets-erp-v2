
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname,'data');
const MASTER = path.join(DATA,'Assets_Master_Data.json');
const INVENTORY = path.join(DATA,'inventory.json');

app.use(express.json({limit:'25mb'}));
app.use(express.static(path.join(__dirname,'public'),{
  setHeaders(res,file){
    if(file.endsWith('.html')){
      res.setHeader('Cache-Control','no-store');
      res.setHeader('Permissions-Policy','camera=(self)');
    }
  }
}));

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

app.get('/api/health',(req,res)=>res.json({ok:true,app:'Assets Pro',version:'3.3.2',time:new Date().toISOString()}));

app.get('/api/master-data',(req,res)=>{
  res.json(readJSON(MASTER,{schema:'assets-pro-master-data-v1',assets:[]}));
});

app.put('/api/master-data',(req,res)=>{
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

app.post('/api/inventory/sync',(req,res)=>{
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

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT,'0.0.0.0',()=>console.log(`Assets Pro running on port ${PORT}`));
