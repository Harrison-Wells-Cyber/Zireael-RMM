'use strict';
let selectedDevice=null, commandAbort=null, fileAbort=null, desktopSocket=null, desktopViewer=null;
// Matching MeshCentral viewer uses this byte encoder for Unicode input.
function ShortToStr(x){return String.fromCharCode((x>>8)&255,x&255);}
function openSupport(device){
  closeSupport(); selectedDevice=device;
  $('support-name').textContent=device.name;
  $('close-support').textContent=device.mode==='temporary'?'End support session':'Close tools';
  $('support-privilege').textContent=device.mode==='service' ? 'Commands run as LocalSystem. Desktop uses the active console session.' : `Commands and files use ${device.details?.username || 'the agent user'}’s ${device.details?.elevated?'elevated':'standard user'} permissions.`;
  $('support').hidden=false;showPage('detail');
}
function closeSupport(){
  commandAbort?.abort();fileAbort?.abort();disconnectDesktop();selectedDevice=null;
  $('support').hidden=true;$('command-output').textContent='';$('command-script').value='';$('command-status').textContent='';$('file-status').textContent='';
}
function endpoint(action){if(!selectedDevice)throw new Error('Select an online device first.');return `/api/devices/${encodeURIComponent(selectedDevice.id)}/${action}`;}
async function checked(response){if(!response.ok){let data;try{data=await response.json();}catch{}if(response.status===401)await refreshSession();throw new Error(data?.error || `Request failed (${response.status}).`);}return response;}
function jsonRequest(body,signal){return {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-RMM-Request':'1'},body:JSON.stringify(body),signal};}
$('close-support').onclick=async()=>{const device=selectedDevice;try{if(device?.mode==='temporary')await api(`/api/devices/${encodeURIComponent(device.id)}/disconnect`,{});closeSupport();showPage('agents');await refreshDevices();}catch(error){$('message').textContent=error.message;}};
for(const tab of ['desktop','command','files'])$('tab-'+tab).onclick=()=>{for(const name of ['desktop','command','files']){$('panel-'+name).hidden=name!==tab;$('tab-'+name).setAttribute('aria-pressed',String(name===tab));}};
$('command-cancel').onclick=()=>commandAbort?.abort();
$('command-run').onclick=async()=>{
  if(commandAbort)return;
  const controller=commandAbort=new AbortController();const button=$('command-run');button.disabled=true;
  $('command-output').textContent='';$('command-status').textContent='Running…';
  try{
    const response=await checked(await fetch(endpoint('command'),jsonRequest({script:$('command-script').value,timeout:Number($('command-timeout').value)},controller.signal)));
    const reader=response.body.getReader(), decoder=new TextDecoder(), outputDecoder=new TextDecoder();let pending='',done=false;
    for(;;){
      const chunk=await reader.read();pending+=decoder.decode(chunk.value,{stream:!chunk.done});
      
      let newline;
      while((newline=pending.indexOf('\n'))>=0){
        const result=JSON.parse(pending.slice(0,newline));pending=pending.slice(newline+1);
        if(result.type==='output'){
          const bytes=Uint8Array.from(atob(result.data),c=>c.charCodeAt(0));
          $('command-output').append(document.createTextNode(outputDecoder.decode(bytes,{stream:true})));
          $('command-output').scrollTop=$('command-output').scrollHeight;
        }else{done=true;$('command-output').append(document.createTextNode(outputDecoder.decode()));$('command-status').textContent=result.error || `Finished · exit code ${result.exitCode || 0}`;}
      }
      if(pending.length>100000)throw new Error('Invalid response size.');
      if(chunk.done)break;
    }
    if(!done)throw new Error('Command connection ended before a result arrived.');
  }catch(error){$('command-status').textContent=error.name==='AbortError'?'Command cancelled.':error.message;}
  finally{controller.abort();if(commandAbort===controller)commandAbort=null;button.disabled=false;}
};
$('file-cancel').onclick=()=>fileAbort?.abort();
async function transfer(kind){
  if(fileAbort)return;
  const controller=fileAbort=new AbortController();
  $('file-status').textContent=kind==='upload'?'Uploading…':'Downloading…';
  let destination;
  try{
    const target=endpoint(kind);
    const remotePath=$('file-path').value;
    if(kind==='upload'){
      const file=$('file-upload').files[0];if(!file)throw new Error('Choose a file first.');if(file.size>1073741824)throw new Error('Maximum file size is 1 GiB.');
      const response=await checked(await fetch(target,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/octet-stream','X-RMM-Request':'1','X-RMM-Path':encodeURIComponent(remotePath),'X-RMM-Size':String(file.size)},body:file,signal:controller.signal}));
      const result=await response.json();$('file-status').textContent=`Uploaded ${result.size.toLocaleString()} bytes.`;
    }else{
      const name=remotePath.replaceAll('\\','/').split('/').pop() || 'download';
      // Browsers supporting the file picker write incrementally to disk.
      if(window.showSaveFilePicker){
        const handle=await window.showSaveFilePicker({suggestedName:name});
        // Closing tools or switching devices while the picker is open cancels
        // the operation before opening a local output file or requesting data.
        controller.signal.throwIfAborted();
        destination=await handle.createWritable();
      }
      controller.signal.throwIfAborted();
      const response=await checked(await fetch(target,jsonRequest({path:remotePath},controller.signal)));
      const size=Number(response.headers.get('Content-Length'));
      if(destination){await response.body.pipeTo(destination,{signal:controller.signal});destination=null;}
      else{
        if(size>128*1024*1024)throw new Error('For downloads above 128 MiB, use Chrome or Edge with its save-file picker.');
        const blob=await response.blob();if(blob.size!==size)throw new Error('Download was incomplete.');
        const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);
      }
      $('file-status').textContent=`Downloaded ${size.toLocaleString()} bytes.`;
    }
  }catch(error){$('file-status').textContent=error.name==='AbortError'?'Transfer cancelled.':error.message;}
  finally{if(destination)await destination.abort().catch(()=>{});controller.abort();if(fileAbort===controller)fileAbort=null;}
}
$('file-send').onclick=()=>transfer('upload');$('file-get').onclick=()=>transfer('download');
function disconnectDesktop(){
  const socket=desktopSocket;desktopSocket=null;
  if(desktopViewer){desktopViewer.handleReleaseKeys();desktopViewer.xxStateChange(0);desktopViewer=null;}
  if(socket)socket.close();$('desktop-status').textContent='Desktop disconnected.';
}
$('desktop-disconnect').onclick=disconnectDesktop;
$('desktop-connect').onclick=()=>{
  if(desktopSocket)return;
  try{
    const url=new URL(endpoint('desktop'),location.href);url.protocol='wss:';
    const socket=desktopSocket=new WebSocket(url,'rmm-desktop-v1');socket.binaryType='arraybuffer';
    const viewer=desktopViewer=CreateAgentRemoteDesktop($('desktop-canvas'),$('desktop-scroll'));viewer.Start();viewer.ScreenWidth=0;viewer.ScreenHeight=0;
    viewer.parent={send(data){if(socket.readyState!==WebSocket.OPEN)return;if(socket.bufferedAmount>1048576){disconnectDesktop();return;}socket.send(typeof data==='string'?Uint8Array.from(data,c=>c.charCodeAt(0)):data);},setConsoleMessage(text){$('desktop-status').textContent=text;}};
    viewer.onMessage=text=>{$('desktop-status').textContent=text;};
    viewer.onDisplayinfo=(_,displays,selected)=>{$('desktop-monitor').replaceChildren(...Object.entries(displays).map(([id,name])=>{const option=new Option(name,id);option.selected=String(selected)===id;return option;}));};
    socket.onopen=()=>{viewer.xxStateChange(3);viewer.GrabMouseInput();viewer.SendCompressionLevel(1,60,1024,100);viewer.SendUnPause();viewer.SendRefresh();$('desktop-status').textContent='Connected. Click the desktop to type.';};
    socket.onmessage=event=>{
      if(typeof event.data==='string'){$('desktop-status').textContent=event.data;return;}
      const data=new Uint8Array(event.data);if(data.length<4||data.length>8388608){disconnectDesktop();return;}
      const cmd=(data[0]<<8)|data[1];
      if(cmd===7){const w=(data[4]<<8)|data[5],h=(data[6]<<8)|data[7];if(data.length!==8||!w||!h||w>16384||h>16384||w*h>67108864){disconnectDesktop();return;}}
      if(viewer.tilesReceived-viewer.TilesDrawn>256){disconnectDesktop();$('desktop-status').textContent='Viewer could not keep up; reconnect to continue.';return;}
      viewer.ProcessBinaryCommand(cmd,data.length,data);
    };
    socket.onerror=()=>{$('desktop-status').textContent='Desktop connection failed. Refresh devices or sign in again.';};
    socket.onclose=event=>{if(desktopSocket===socket){disconnectDesktop();$('desktop-status').textContent=event.reason || 'Desktop connection ended.';}};
    $('desktop-status').textContent='Starting desktop…';
  }catch(error){disconnectDesktop();$('desktop-status').textContent=error.message;}
};
$('desktop-canvas').addEventListener('focus',()=>desktopViewer?.GrabKeyInput());
$('desktop-canvas').addEventListener('blur',()=>{desktopViewer?.handleReleaseKeys();desktopViewer?.UnGrabKeyInput();});
$('desktop-canvas').addEventListener('mousedown',()=>$('desktop-canvas').focus());
$('desktop-canvas').addEventListener('contextmenu',event=>event.preventDefault());
$('desktop-refresh').onclick=()=>desktopViewer?.SendRefresh();
$('desktop-monitor').onchange=()=>desktopViewer?.SetDisplay(Number($('desktop-monitor').value));
window.addEventListener('blur',()=>desktopViewer?.handleReleaseKeys());
window.addEventListener('pagehide',closeSupport);
