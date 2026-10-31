'use strict';
(async()=>{
 const status=document.getElementById('desktop-status');
 const response=await fetch('/api/session',{credentials:'same-origin'});const session=await response.json();
 if(!session.authenticated){status.textContent='Sign in through the console, then reconnect here.';return;}
 const id=new URLSearchParams(location.search).get('device');if(!/^[a-f0-9]{64}$/.test(id||'')){status.textContent='Choose a device from the console.';return;}
 const devices=await fetch('/api/devices',{credentials:'same-origin'});if(!devices.ok)throw Error('Sign in again through the console.');const device=(await devices.json()).find(d=>d.id===id&&!d.revoked&&!d.pending);if(!device)throw Error('Device unavailable.');document.getElementById('device-name').textContent=device.name;
 const viewer=new DesktopViewer(document.getElementById('panel-desktop'));viewer.deviceID=id;
 viewer.connect();
})().catch(e=>{document.getElementById('desktop-status').textContent=e.message;});
