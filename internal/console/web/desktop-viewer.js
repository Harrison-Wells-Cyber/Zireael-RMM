'use strict';
// Shared by the embedded console and the dedicated desktop window.
class DesktopViewer {
  constructor(root) {
    this.root=root;this.el=id=>root.querySelector('#desktop-'+id);this.canvas=this.el('canvas');this.ctx=this.canvas.getContext('2d',{alpha:false});this.socket=null;this.generation=0;this.ready=false;this.sequence=0;this.keys=new Set();this.buttons=new Set();this.controller=new AbortController();this.streamEpoch=0;this.connecting=false;
    const on=(target,name,fn)=>target.addEventListener(name,fn,{signal:this.controller.signal});
    on(this.el('connect'),'click',()=>this.connect());on(this.el('disconnect'),'click',()=>this.disconnect());
    on(this.el('session'),'change',()=>{this.sessionChoice=Number(this.el('session').value);if(this.socket){this.disconnect();this.connect();}});
    on(this.el('elevated'),'change',()=>{if(this.socket){this.disconnect();this.connect();}});
    on(this.el('monitor'),'change',()=>{this.releaseInput();this.ready=false;this.send({type:'select-monitor',monitorID:Number(this.el('monitor').value),generation:this.generation});});
    for(const id of ['quality','view-only','backend'])on(this.el(id),'change',()=>{this.releaseInput();this.send(this.settings('settings'));});
    on(this.el('fit'),'click',()=>{this.el('scroll').classList.toggle('actual-size');this.el('fit').textContent=this.el('scroll').classList.contains('actual-size')?'Fit to window':'Actual size';});
    on(this.el('fullscreen'),'click',async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await root.requestFullscreen();}catch{this.status('Fullscreen is unavailable in this browser.');}});
    on(document,'fullscreenchange',()=>{this.releaseInput();this.el('fullscreen').textContent=document.fullscreenElement?'Exit fullscreen':'Fullscreen';});
    on(window,'blur',()=>this.releaseInput());on(this.canvas,'blur',()=>this.releaseInput());on(window,'pagehide',()=>this.disconnect());on(document,'visibilitychange',()=>{if(document.hidden)this.disconnect('Desktop paused. Reconnect when ready.');});
    on(this.canvas,'contextmenu',e=>e.preventDefault());
    on(this.canvas,'pointerdown',e=>{if(!this.canInput())return;e.preventDefault();this.canvas.focus();this.canvas.setPointerCapture(e.pointerId);this.buttons.add(e.button);this.pointer(e,'down');});
    on(this.canvas,'pointerup',e=>{if(!this.buttons.has(e.button))return;e.preventDefault();this.buttons.delete(e.button);this.pointer(e,'up');});
    on(this.canvas,'pointercancel',()=>this.releaseInput());
    let moved=0;on(this.canvas,'pointermove',e=>{if(performance.now()-moved<17)return;moved=performance.now();this.pointer(e,'move');});
    this.canvas.addEventListener('wheel',e=>{if(this.canInput()){e.preventDefault();this.pointer(e,'wheel',Math.max(-1200,Math.min(1200,-Math.sign(e.deltaY)*120)));}},{passive:false,signal:this.controller.signal});
    for(const type of ['keydown','keyup'])on(this.canvas,type,e=>{if(!this.canInput()||!DesktopViewer.codes.has(e.code))return;e.preventDefault();const down=type==='keydown';if(down)this.keys.add(e.code);else this.keys.delete(e.code);this.send({type:'key',generation:this.generation,code:e.code,down,repeat:e.repeat});});
    on(this.el('send-text'),'click',()=>{const text=this.el('text').value;if(this.canInput()&&text&&new TextEncoder().encode(text).length<=1024){this.send({type:'text',generation:this.generation,text});this.el('text').value='';}});
  }
  status(text){this.el('status').textContent=text;}
  settings(type){const quality=this.el('quality').value;const preset={balanced:[10,1920,70],sharp:[8,2560,85],fast:[6,1280,50]}[quality];return {type,viewOnly:this.el('view-only').checked,maxFPS:preset[0],maxEdge:preset[1],quality:preset[2],backend:this.el('backend').value};}
  canInput(){return this.ready&&!this.el('view-only').checked&&this.socket?.readyState===WebSocket.OPEN;}
  encode(c){const data=new TextEncoder().encode(JSON.stringify(c));const p=new Uint8Array(12+data.length);p.set([90,82,68,50,1,0,0,0]);new DataView(p.buffer).setUint32(8,data.length);p.set(data,12);return p;}
  send(c){const socket=this.socket;if(socket?.readyState!==WebSocket.OPEN)return;if(socket.bufferedAmount>65536){this.disconnect('Connection is too slow. Reconnect to continue.');return;}socket.send(this.encode(c));}
  pointer(e,action,delta=0){if(!this.canInput())return;const r=this.canvas.getBoundingClientRect();if(!r.width||!r.height)return;const x=Math.max(0,Math.min(this.canvas.width-1,Math.floor((e.clientX-r.left)*this.canvas.width/r.width)));const y=Math.max(0,Math.min(this.canvas.height-1,Math.floor((e.clientY-r.top)*this.canvas.height/r.height)));this.send({type:'pointer',generation:this.generation,x,y,action,button:action==='down'||action==='up'?e.button:0,delta});}
  releaseInput(){this.send({type:'release-input'});this.keys.clear();this.buttons.clear();}
  disconnect(message='Desktop disconnected.') {
    const socket=this.socket;this.socket=null;this.streamEpoch++;
    this.releaseInput();
    if(socket?.readyState===WebSocket.OPEN){try{socket.send(this.encode({type:'release-input'}));socket.send(this.encode({type:'stop'}));}catch{}}
    socket?.close();this.ready=false;this.generation=0;this.sequence=0;clearInterval(this.heartbeat);clearInterval(this.expiryTimer);this.ctx.clearRect(0,0,this.canvas.width,this.canvas.height);this.status(message);
  }
  destroy(){this.disconnect();this.controller.abort();}
  async connect(){
    if(this.socket||this.connecting||!this.deviceID)return;
    this.connecting=true;this.ready=false;this.sequence=0;this.generation=0;const epoch=++this.streamEpoch;this.status('Checking console session…');
    try{const response=await fetch('/api/session',{credentials:'same-origin',cache:'no-store'});const session=await response.json();if(!response.ok||!session.authenticated){this.status('Sign in through the console, then reconnect.');this.connecting=false;return;}}catch{this.status('Unable to confirm the console session. Sign in again.');this.connecting=false;return;}
    if(epoch!==this.streamEpoch){this.connecting=false;return;}
    this.connecting=false;this.status('Starting desktop…');
    const url=new URL(`/api/devices/${encodeURIComponent(this.deviceID)}/desktop-v2`,location.href);url.protocol='wss:';
    const socket=this.socket=new WebSocket(url,'zireael-desktop-v2');socket.binaryType='arraybuffer';let queue=Promise.resolve();let queued=0;let lastSeen=Date.now();const opened=Date.now();
    socket.onopen=()=>{this.heartbeat=setInterval(()=>{if(Date.now()-lastSeen>15000)this.disconnect('Desktop connection timed out.');else this.send({type:'ping',nonce:Math.floor(Date.now()/1000)>>>0});},5000);this.expiryTimer=setInterval(()=>{this.el('expiry').textContent=`Session expires in ${Math.max(0,20-Math.floor((Date.now()-opened)/60000))} min`;},1000);};
    socket.onmessage=event=>{lastSeen=Date.now();if(++queued>8){this.disconnect('Viewer could not keep up.');return;}queue=queue.then(async()=>{if(this.socket!==socket)return;await this.message(event.data,epoch);}).catch(()=>{if(this.socket===socket)this.disconnect('Invalid desktop response.');}).finally(()=>queued--);};
    socket.onerror=()=>{if(this.socket===socket)this.status('Desktop connection failed. Sign in again or refresh the device list.');};
    socket.onclose=()=>{if(this.socket===socket){const text=this.el('status').textContent;this.disconnect(this.errorStatus?text:'Desktop connection ended.');}};
    this.errorStatus=false;
  }
  async message(buffer,epoch){
    if(!(buffer instanceof ArrayBuffer)||buffer.byteLength<12||buffer.byteLength>8388620)throw Error();const p=new Uint8Array(buffer),v=new DataView(buffer);if(v.getUint32(0)!==0x5a524432||v.getUint8(5)||v.getUint16(6)||v.getUint32(8)!==p.length-12)throw Error();
    if(p[4]===1){if(p.length>16396)throw Error();const c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(p.subarray(12)));
      switch(c.type){
      case 'hello':{
        if(c.protocol!==2||!Array.isArray(c.sessions)||c.sessions.length>16)throw Error();const select=this.el('session');select.replaceChildren(...c.sessions.map(s=>new Option(s.label,String(s.id))));const choice=c.sessions.some(s=>s.id===this.sessionChoice)?this.sessionChoice:c.defaultSession;if(choice!==undefined)select.value=String(choice);
        this.el('privilege').hidden=!c.elevatedAvailable;
        if(choice!==undefined)this.start();else{this.status('Choose a Windows session, then click Start session.');}
        this.el('start').onclick=()=>this.start();this.el('start').disabled=false;break;
      }
      case 'geometry':
        if(!c.generation||!Array.isArray(c.monitors)||c.monitors.length>16||c.generation<this.generation)throw Error();this.releaseInput();this.generation=c.generation;this.ready=false;this.el('monitor').replaceChildren(...c.monitors.map(m=>new Option(m.label,String(m.id))));this.el('monitor').value=String(c.selectedMonitor);break;
      case 'status':
        this.onStatus?.(c);
        this.el('backend-label').textContent=c.backend?`${c.backend.toUpperCase()} · ${c.elevated?'Elevated':'User'}`:'';
        if(c.state==='error'){this.errorStatus=true;this.status(c.message||c.code);this.ready=false;}
        else if(c.state==='paused'){this.status(c.message||c.code);this.ready=false;this.releaseInput();}
        else if(c.state!=='streaming'||!this.ready)this.status(c.message||'Starting capture…');break;
      case 'ping':this.send({type:'pong',nonce:c.nonce||0});break;
      case 'pong':break;
      default:throw Error();
      }return;
    }
    if(p[4]!==2||p.length<37||this.decoding)throw Error();const seq=v.getUint32(12),gen=v.getUint32(16),w=v.getUint32(24),h=v.getUint32(28);if(!seq||seq<=this.sequence||v.getUint32(32)||!w||!h||w>2560||h>2560||w*h>16777216)throw Error();if(gen!==this.generation)return;
    this.decoding=true;let bitmap;try{bitmap=await createImageBitmap(new Blob([p.subarray(36)],{type:'image/jpeg'}));if(this.streamEpoch!==epoch||gen!==this.generation)return;if(bitmap.width!==w||bitmap.height!==h)throw Error();this.canvas.width=w;this.canvas.height=h;this.ctx.drawImage(bitmap,0,0);this.sequence=seq;this.ready=true;this.send({type:'ack',sequence:seq,generation:gen});this.status('Connected. Click the desktop to use keyboard and mouse.');}finally{bitmap?.close();this.decoding=false;}
  }
  start(){if(this.startedEpoch===this.streamEpoch)return;this.startedEpoch=this.streamEpoch;this.el('start').disabled=true;this.send({...this.settings('start'),sessionID:Number(this.el('session').value),privilege:this.el('elevated').checked?'elevated':'user'});this.status('Starting capture…');}
}
DesktopViewer.codes=new Set(('Escape Backspace Tab Enter ControlLeft ControlRight ShiftLeft ShiftRight AltLeft AltRight MetaLeft MetaRight Space CapsLock Minus Equal BracketLeft BracketRight Semicolon Quote Backquote Backslash Comma Period Slash NumLock ScrollLock NumpadMultiply NumpadDivide NumpadAdd NumpadSubtract NumpadEnter NumpadDecimal IntlBackslash PrintScreen Home End ArrowUp ArrowDown ArrowLeft ArrowRight PageUp PageDown Insert Delete ContextMenu '+Array.from({length:26},(_,i)=>'Key'+String.fromCharCode(65+i)).join(' ')+' '+Array.from({length:10},(_,i)=>'Digit'+i+' Numpad'+i).join(' ')+' '+Array.from({length:12},(_,i)=>'F'+(i+1)).join(' ')).split(' '));
