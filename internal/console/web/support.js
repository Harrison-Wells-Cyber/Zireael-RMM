'use strict';
let selectedDevice=null, commandAbort=null, fileAbort=null, desktopViewer=null;
function openSupport(device){
  closeSupport(); selectedDevice=device;
  $('support-name').textContent=device.name;
  $('close-support').textContent=device.mode==='temporary'?'End support session':'Close tools';
  $('support-privilege').textContent=device.mode==='service' ? 'Commands run as LocalSystem. Choose an interactive session for desktop.' : `Commands and files use ${device.details?.username || 'the agent user'}’s ${device.details?.elevated?'elevated':'standard user'} permissions.`;
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
function disconnectDesktop(){desktopViewer?.disconnect();}
$('desktop-connect').onclick=()=>{if(!selectedDevice)return;if(!desktopViewer)desktopViewer=new DesktopViewer($('panel-desktop'));desktopViewer.deviceID=selectedDevice.id;desktopViewer.connect();};
$('desktop-popout').onclick=()=>{if(!selectedDevice)return;const popup=window.open(`/admin/desktop?device=${encodeURIComponent(selectedDevice.id)}`,'_blank','popup,width=1440,height=950');if(popup){disconnectDesktop();popup.opener=null;}else $('desktop-status').textContent='Allow popups to open the desktop window.';};
window.addEventListener('pagehide',closeSupport);
