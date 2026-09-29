import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { parseHTML } from 'linkedom';
import * as state from '../src/state.js';
test('Connect uses progress, confirms access and recovers after failure', async t => {
 const root=fileURLToPath(new URL('..', import.meta.url));
 const {window,document}=parseHTML(fs.readFileSync(root+'/index.html','utf8'));
 let running=false,report=null,scenario='success', releaseAttempt;
 const until = async predicate => {
   const deadline=Date.now()+2000;
   while (!predicate()) {
     if (Date.now()>deadline) throw new Error('UI condition timed out');
     await new Promise(resolve=>setTimeout(resolve,5));
   }
 };
 const intervals=[];
 t.after(() => intervals.forEach(clearInterval));
 const probes={results:['youtube-web','youtube-image','discord-api','discord-cdn'].map(target=>({target,ok:true}))};
 const invoke=async(command,args={})=>{
  if(command==='app_version')return 'test';
  if(command==='default_profile')return {available:true,platform:'windows'};
  if(command==='session_selection')return JSON.stringify(report);
  if(command==='session_health')return `session_present=${running}\nrunning=${running}\nengine_alive=${running}\nnetwork_resource=${running}\nsession_id=${running?'live-session':''}\n`;
  if(command==='session_stop'){running=false;return 'stopped'}
  if(command==='session_start_default'){
   assert.equal(args.profile,'auto');assert.ok(args.requestId);
   report={outcome:'checking',request_id:args.requestId,message:'Проверка кандидата…',attempts:[]};
   await new Promise(resolve=>{ releaseAttempt=resolve; });
   running=scenario==='success';
   report={request_id:args.requestId,outcome:running?'connected':'failed',message:running?'HTTPS подтверждён':'Подходящая стратегия не найдена',strategy:running?'split':null,session_id:running?'live-session':null,coverage:'QUIC и голос не проверены',attempts:running?[{strategy:'split',probes,confirmation:probes}]:[]};
   return JSON.stringify(report);
  }
  throw new Error('Unexpected command: '+command);
 };
 const main=fs.readFileSync(root+'/src/main.js','utf8').replace(/^import .*;\n/gm,'');
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const run=new AsyncFunction('document','window','localStorage','crypto','invoke','isTauri','listen','parseHealth','friendlyError','parseSelection','verifiedSelection','setInterval','clearInterval',main);
 await run(document,window,{getItem:()=>null,setItem:()=>{}},webcrypto,invoke,()=>true,async()=>{},state.parseHealth,state.friendlyError,state.parseSelection,state.verifiedSelection,(fn,ms)=>{const id=setInterval(fn,ms===1200?15:100000);intervals.push(id);return id},clearInterval);
 const el=id=>document.getElementById(id);
 assert.equal(el('profile').value,'auto');
 assert.equal(el('toggle').disabled,false);
 el('toggle').dispatchEvent(new window.Event('click'));
 await until(()=>el('state-detail').textContent==='Проверка кандидата…');
 assert.equal(el('state-detail').textContent,'Проверка кандидата…');
 releaseAttempt();
 await until(()=>!el('toggle').disabled);
 assert.equal(el('state').textContent,'Подключено');
 assert.equal(el('toggle').textContent,'Отключить');
 el('toggle').dispatchEvent(new window.Event('click'));
 await until(()=>!el('toggle').disabled);
 assert.equal(running,false);
 assert.equal(el('toggle').textContent,'Подключиться');
 scenario='failed'; releaseAttempt=null;
 el('toggle').dispatchEvent(new window.Event('click'));
 await until(()=>releaseAttempt);
 releaseAttempt();
 await until(()=>!el('toggle').disabled);
 assert.equal(el('state').textContent,'Операция не завершена');
 assert.equal(el('recover').disabled,false);
 assert.equal(el('toggle').textContent,'Подключиться');
 assert.equal(running,false);
 intervals.forEach(clearInterval);

});
