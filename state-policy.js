'use strict';

const STATE_PARTITIONS={
  core:['assets','masterdata','settings','custody'],
  finance:['depreciation','journals','financialdash','assetbudget','deprforecast','reconciliation'],
  hr:['hrlink','employeesDirectory','custody','integratedcost'],
  maintenance:['maintenance','maintdash','warranty','vendors']
};

function partitionForKey(key){
  key=String(key||'');
  if(/^hr_/i.test(key)||/^assetsPro(?:HR|Employees|Custody)/.test(key))return 'hr';
  if(/^assetsPro(?:Dep|Closed|AssetBudget|Budget|Reconciliation)/.test(key))return 'finance';
  if(/^assetsPro(?:Maintenance|Warranty|Vendor)/.test(key))return 'maintenance';
  if(/^assetsPro/.test(key)&&!/^assetsPro(?:Users|Recovery|ServerAudit|AuditTrail|ActivityLog|RuntimeErrors|Inventory|Journals|Assets$|MasterData$)/.test(key))return 'core';
  return '';
}

function canPartition(user,partition,write=false){
  if(!STATE_PARTITIONS[partition])return false;
  if(user?.role==='Admin')return true;
  if(write&&user?.role==='Viewer')return false;
  return Array.isArray(user?.pages)&&STATE_PARTITIONS[partition].some(page=>user.pages.includes(page));
}

function pagesForKey(key){
  const part=partitionForKey(key);key=String(key||'');
  if(part==='hr')return /Custody/.test(key)?['custody']:['hrlink','employeesDirectory','integratedcost'];
  if(part==='finance'){
    if(/AssetBudget|Budget/.test(key))return ['assetbudget'];
    if(/Reconciliation/.test(key))return ['reconciliation'];
    return ['depreciation','financialdash','deprforecast'];
  }
  if(part==='maintenance'){
    if(/Warranty/.test(key))return ['warranty'];
    if(/Vendor/.test(key))return ['vendors'];
    return ['maintenance','maintdash'];
  }
  if(part==='core'){
    if(/Settings/.test(key))return ['settings'];
    if(/Branches|Reference|Lookup/.test(key))return ['masterdata'];
    if(/AssetMovements|Label|Print/.test(key))return ['assets','custody','labels'];
    return ['assets','masterdata'];
  }
  return [];
}

function canKey(user,key,write=false){
  if(!partitionForKey(key))return false;
  if(user?.role==='Admin')return true;
  if(write&&user?.role==='Viewer')return false;
  const allowed=pagesForKey(key);
  return Array.isArray(user?.pages)&&allowed.some(page=>user.pages.includes(page));
}

module.exports={STATE_PARTITIONS,partitionForKey,canPartition,pagesForKey,canKey};
