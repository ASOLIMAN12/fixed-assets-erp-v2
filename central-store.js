'use strict';

const crypto = require('crypto');

function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value && typeof value === 'object'){
    return Object.keys(value).sort().reduce((out,key)=>{out[key]=canonical(value[key]);return out},{});
  }
  return value;
}

function checksum(payload){
  return crypto.createHash('sha256').update(JSON.stringify(canonical(payload))).digest('hex');
}

function cleanPayload(value){
  const payload = value && typeof value === 'object' && !Array.isArray(value) ? {...value} : value;
  if(payload && typeof payload === 'object'){
    delete payload._serverVersion;
    delete payload._checksum;
    delete payload._updatedAt;
  }
  return payload;
}

function createCentralStore(pool){
  if(!pool)throw new Error('Central store requires a PostgreSQL pool');

  async function init(){
    await pool.query(`
      CREATE TABLE IF NOT EXISTS assetspro_documents (
        document_key TEXT PRIMARY KEY,
        payload JSONB NOT NULL,
        version BIGINT NOT NULL DEFAULT 1,
        checksum TEXT NOT NULL,
        updated_by BIGINT REFERENCES assetspro_users(id) ON DELETE SET NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS assetspro_document_versions (
        id BIGSERIAL PRIMARY KEY,
        document_key TEXT NOT NULL,
        version BIGINT NOT NULL,
        payload JSONB NOT NULL,
        checksum TEXT NOT NULL,
        changed_by BIGINT REFERENCES assetspro_users(id) ON DELETE SET NULL,
        change_reason TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(document_key, version)
      );
      CREATE INDEX IF NOT EXISTS assetspro_document_versions_lookup_idx
        ON assetspro_document_versions(document_key, version DESC);
      CREATE TABLE IF NOT EXISTS assetspro_audit_log (
        id BIGSERIAL PRIMARY KEY,
        actor_id BIGINT REFERENCES assetspro_users(id) ON DELETE SET NULL,
        actor_username TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        details JSONB NOT NULL DEFAULT '{}'::jsonb,
        ip_address TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS assetspro_audit_log_created_idx ON assetspro_audit_log(created_at DESC);
      CREATE TABLE IF NOT EXISTS assetspro_attachments (
        asset_number TEXT NOT NULL,
        attachment_type TEXT NOT NULL,
        file_name TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size BIGINT NOT NULL,
        checksum TEXT NOT NULL,
        content BYTEA NOT NULL,
        updated_by BIGINT REFERENCES assetspro_users(id) ON DELETE SET NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY(asset_number,attachment_type)
      );
      CREATE INDEX IF NOT EXISTS assetspro_attachments_updated_idx ON assetspro_attachments(updated_at DESC);
    `);
  }

  async function seed(documentKey, input){
    const payload=cleanPayload(input);
    await pool.query(`INSERT INTO assetspro_documents(document_key,payload,version,checksum)
      VALUES($1,$2::jsonb,1,$3) ON CONFLICT(document_key) DO NOTHING`,
      [documentKey,JSON.stringify(payload),checksum(payload)]);
  }

  async function read(documentKey){
    const result=await pool.query('SELECT * FROM assetspro_documents WHERE document_key=$1',[documentKey]);
    const row=result.rows[0];
    if(!row)return null;
    const actual=checksum(row.payload);
    if(actual!==row.checksum)throw Object.assign(new Error(`Integrity check failed for ${documentKey}`),{code:'DATA_INTEGRITY_FAILED'});
    return {key:row.document_key,payload:row.payload,version:Number(row.version),checksum:row.checksum,updatedAt:row.updated_at};
  }

  async function write(documentKey,input,context={}){
    const payload=cleanPayload(input), expectedVersion=Number.isFinite(Number(context.expectedVersion))?Number(context.expectedVersion):null;
    const nextChecksum=checksum(payload), client=await pool.connect();
    try{
      await client.query('BEGIN');
      const currentResult=await client.query('SELECT * FROM assetspro_documents WHERE document_key=$1 FOR UPDATE',[documentKey]);
      const current=currentResult.rows[0];
      if(current && expectedVersion!==null && Number(current.version)!==expectedVersion){
        await client.query('ROLLBACK');
        throw Object.assign(new Error('تم تعديل البيانات من جهاز آخر. أعد تحميل أحدث نسخة ثم كرر العملية.'),{code:'VERSION_CONFLICT',status:409,currentVersion:Number(current.version)});
      }
      let version=1;
      if(current){
        if(checksum(current.payload)!==current.checksum){
          await client.query('ROLLBACK');
          throw Object.assign(new Error('فشل فحص سلامة البيانات الحالية.'),{code:'DATA_INTEGRITY_FAILED',status:500});
        }
        await client.query(`INSERT INTO assetspro_document_versions(document_key,version,payload,checksum,changed_by,change_reason)
          VALUES($1,$2,$3::jsonb,$4,$5,$6) ON CONFLICT(document_key,version) DO NOTHING`,
          [documentKey,Number(current.version),JSON.stringify(current.payload),current.checksum,context.userId||null,String(context.reason||'تحديث مركزي').slice(0,300)]);
        version=Number(current.version)+1;
        await client.query(`UPDATE assetspro_documents SET payload=$2::jsonb,version=$3,checksum=$4,updated_by=$5,updated_at=NOW()
          WHERE document_key=$1`,[documentKey,JSON.stringify(payload),version,nextChecksum,context.userId||null]);
      }else{
        await client.query(`INSERT INTO assetspro_documents(document_key,payload,version,checksum,updated_by)
          VALUES($1,$2::jsonb,1,$3,$4)`,[documentKey,JSON.stringify(payload),nextChecksum,context.userId||null]);
      }
      await client.query(`INSERT INTO assetspro_audit_log(actor_id,actor_username,action,entity_type,entity_key,details,ip_address)
        VALUES($1,$2,'UPDATE','document',$3,$4::jsonb,$5)`,[context.userId||null,String(context.username||''),documentKey,JSON.stringify({version,reason:String(context.reason||'').slice(0,300),checksum:nextChecksum}),String(context.ip||'').slice(0,100)]);
      const old=await client.query(`SELECT id FROM assetspro_document_versions WHERE document_key=$1 ORDER BY version DESC OFFSET 50`,[documentKey]);
      if(old.rows.length)await client.query('DELETE FROM assetspro_document_versions WHERE id = ANY($1::bigint[])',[old.rows.map(x=>x.id)]);
      await client.query('COMMIT');
      return {key:documentKey,payload,version,checksum:nextChecksum,updatedAt:new Date()};
    }catch(error){
      try{await client.query('ROLLBACK')}catch(_){/* transaction may already be closed */}
      throw error;
    }finally{client.release()}
  }

  async function versions(documentKey){
    const result=await pool.query(`SELECT version,checksum,change_reason,created_at FROM assetspro_document_versions
      WHERE document_key=$1 ORDER BY version DESC LIMIT 50`,[documentKey]);
    return result.rows.map(x=>({version:Number(x.version),checksum:x.checksum,reason:x.change_reason,createdAt:x.created_at}));
  }

  async function audit(limit=200){
    const result=await pool.query(`SELECT id,actor_username,action,entity_type,entity_key,details,ip_address,created_at
      FROM assetspro_audit_log ORDER BY id DESC LIMIT $1`,[Math.max(1,Math.min(1000,Number(limit)||200))]);
    return result.rows;
  }

  async function restore(documentKey,version,context={}){
    const selected=await pool.query(`SELECT payload FROM assetspro_document_versions
      WHERE document_key=$1 AND version=$2`,[documentKey,Number(version)]);
    if(!selected.rows[0])throw Object.assign(new Error('نسخة الاستعادة المطلوبة غير موجودة.'),{status:404,code:'VERSION_NOT_FOUND'});
    const current=await read(documentKey);
    return write(documentKey,selected.rows[0].payload,{...context,expectedVersion:current?.version,reason:`استعادة الإصدار ${version}`});
  }

  async function putAttachment(assetNumber,type,file,context={}){
    const content=Buffer.isBuffer(file.content)?file.content:Buffer.from(file.content||'');
    const digest=crypto.createHash('sha256').update(content).digest('hex');
    const result=await pool.query(`INSERT INTO assetspro_attachments(asset_number,attachment_type,file_name,mime_type,file_size,checksum,content,updated_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT(asset_number,attachment_type) DO UPDATE SET file_name=EXCLUDED.file_name,mime_type=EXCLUDED.mime_type,
      file_size=EXCLUDED.file_size,checksum=EXCLUDED.checksum,content=EXCLUDED.content,updated_by=EXCLUDED.updated_by,updated_at=NOW()
      RETURNING asset_number,attachment_type,file_name,mime_type,file_size,checksum,updated_at`,
      [assetNumber,type,file.name,file.mime,content.length,digest,content,context.userId||null]);
    await pool.query(`INSERT INTO assetspro_audit_log(actor_id,actor_username,action,entity_type,entity_key,details,ip_address)
      VALUES($1,$2,'ATTACHMENT_SAVE','attachment',$3,$4::jsonb,$5)`,[context.userId||null,String(context.username||''),`${assetNumber}:${type}`,JSON.stringify({fileName:file.name,size:content.length,checksum:digest}),String(context.ip||'').slice(0,100)]);
    return result.rows[0];
  }

  async function getAttachment(assetNumber,type,metaOnly=false){
    const fields=metaOnly?'asset_number,attachment_type,file_name,mime_type,file_size,checksum,updated_at':'*';
    const result=await pool.query(`SELECT ${fields} FROM assetspro_attachments WHERE asset_number=$1 AND attachment_type=$2`,[assetNumber,type]);
    const row=result.rows[0];
    if(!row)return null;
    if(!metaOnly){
      const actual=crypto.createHash('sha256').update(row.content).digest('hex');
      if(actual!==row.checksum)throw Object.assign(new Error('فشل فحص سلامة المرفق.'),{code:'ATTACHMENT_INTEGRITY_FAILED',status:500});
    }
    return row;
  }

  async function deleteAttachment(assetNumber,type,context={}){
    const result=await pool.query('DELETE FROM assetspro_attachments WHERE asset_number=$1 AND attachment_type=$2 RETURNING file_name,checksum',[assetNumber,type]);
    if(result.rows[0])await pool.query(`INSERT INTO assetspro_audit_log(actor_id,actor_username,action,entity_type,entity_key,details,ip_address)
      VALUES($1,$2,'ATTACHMENT_DELETE','attachment',$3,$4::jsonb,$5)`,[context.userId||null,String(context.username||''),`${assetNumber}:${type}`,JSON.stringify(result.rows[0]),String(context.ip||'').slice(0,100)]);
    return !!result.rows[0];
  }

  return {init,seed,read,write,versions,audit,restore,putAttachment,getAttachment,deleteAttachment,checksum,cleanPayload};
}

module.exports={createCentralStore,checksum};
