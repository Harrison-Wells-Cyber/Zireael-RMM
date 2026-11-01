'use strict';
const $ = (id) => document.getElementById(id);
let setupRequired = false;
let busy = false;
let packageAvailable = false;
let deviceLabels = new Map();
let adminLabels = new Map();
let currentAdminID = '';
let adminInvite = new URLSearchParams(location.hash.slice(1)).get('admin-invite') || '';
if (adminInvite) history.replaceState(null, '', '/admin');
function eventLabel(action){
 const [kind,id]=action.split(':');
 const labels={'setup.created':'Setup token created','passkey.added':'Passkey registered','auth.login':'Signed in with a passkey','auth.logout':'Signed out','device.invite.created':'Support link created','device.enrolled':'Device enrolled','device.pending':'Approval requested','device.approved':'Device approved','device.rejected':'Device rejected','device.connected':'Device connected','device.disconnected':'Device disconnected','device.revoked':'Access revoked','device.session.ended':'Support session ended'};
 let label=labels[kind];
 if(!label&&kind.startsWith('operation.')){const [,tool,state]=kind.split('.');label=({command:'PowerShell',upload:'Upload',download:'Download',desktop:'Desktop'}[tool]||tool)+' '+state;}
 return (label||kind)+(id?' · '+(deviceLabels.get(id)||id.slice(0,8)):'');
}

function showPage(page) {
  for (const name of ['agents','detail','users']) $('page-'+name).hidden = name !== page;
  $('nav-agents').setAttribute('aria-current', page === 'agents' || page === 'detail' ? 'page' : 'false');
  $('nav-users').setAttribute('aria-current', page === 'users' ? 'page' : 'false');
  window.scrollTo({top:0,behavior:'smooth'});
}
$('nav-agents').addEventListener('click',()=>{if(typeof closeSupport==='function')closeSupport();showPage('agents');});
$('nav-users').addEventListener('click',()=>{if(typeof closeSupport==='function')closeSupport();showPage('users');});
$('back-agents').addEventListener('click',()=>{if(typeof closeSupport==='function')closeSupport();showPage('agents');});

async function api(path, body) {
  const options = {credentials: 'same-origin', cache: 'no-store'};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = {'Content-Type': 'application/json', 'X-RMM-Request': '1'};
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/session' && !path.startsWith('/api/auth/')) await refreshSession();
    throw new Error(result.error || 'Request failed.');
  }
  return result;
}

function supportsPasskeys() {
  if (!window.isSecureContext || !window.PublicKeyCredential ||
      !PublicKeyCredential.parseCreationOptionsFromJSON ||
      !PublicKeyCredential.parseRequestOptionsFromJSON ||
      !PublicKeyCredential.prototype.toJSON) {
    throw new Error('Use a current version of Chrome, Edge, Firefox, or Safari over trusted HTTPS.');
  }
}

async function register() {
  supportsPasskeys();
  const options = await api('/api/auth/register/begin', {setupToken: setupRequired ? $('setup-token').value : '', adminInvite});
  $('setup-token').value = '';
  const credential = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey)});
  if (!credential) throw new Error('No passkey was created.');
  await api('/api/auth/register/finish', credential.toJSON());
  adminInvite = '';
}

async function login() {
  supportsPasskeys();
  const options = await api('/api/auth/login/begin', {name:$('login-name').value});
  const credential = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)});
  if (!credential) throw new Error('Sign-in was cancelled.');
  await api('/api/auth/login/finish', credential.toJSON());
}

async function refreshSession() {
  const session = await api('/api/session');
  setupRequired = session.setupRequired;
	currentAdminID = session.adminID || '';
  $('auth').hidden = session.authenticated;
  $('dashboard').hidden = !session.authenticated;
  $('logout').hidden = !session.authenticated;
  $('setup-label').hidden = !setupRequired;
  $('login-name-label').hidden = setupRequired || !!adminInvite;
  $('auth-title').textContent = setupRequired ? 'Set up your console' : adminInvite ? 'Join the support team' : 'Welcome back';
  $('auth-description').textContent = setupRequired ? 'Enter the setup token created on your server, then register your first passkey.' : adminInvite ? 'Use this private invitation to create your own admin passkey.' : 'Enter your admin name, then use your security key, fingerprint, or device PIN.';
  $('signin').textContent = setupRequired ? 'Create your first passkey' : adminInvite ? 'Create my admin passkey' : 'Sign in with a passkey';
  if (!session.authenticated) { if (typeof closeSupport === 'function') closeSupport(); showPage('agents'); $('installer').hidden = true; $('install-command').value = ''; $('local-install-command').value = ''; $('replace-install-command').value = ''; $('download-exe').hidden = true; $('download-ps1').hidden = true; $('support-link').value = ''; $('preview-link').removeAttribute('href'); }
  return session;
}

async function refresh() {
  const session = await refreshSession();
  if (session.authenticated) {
    const [status, events, admins] = await Promise.all([api('/api/status'), api('/api/audit'), api('/api/admins')]);
	adminLabels = new Map(admins.map(admin=>[admin.id,admin.name]));
	refreshAdmins(admins);
    $('key-count').textContent = `${status.passkeys} registered ${status.passkeys === 1 ? 'passkey' : 'passkeys'}`;
    packageAvailable = status.agentPackageAvailable;
    $('download-exe').hidden = !packageAvailable;
    $('download-ps1').hidden = !packageAvailable;
 $('copy-replace-command').disabled=!packageAvailable;
    $('download-unavailable').hidden = packageAvailable;
    $('package-status').textContent = packageAvailable ? `Windows ${status.agentArchitecture === 'amd64' ? 'x64' : 'ARM64'} agent ready. Create a link for one device.` : 'Build a Windows agent and start the server with --agent-exe to enable installation commands.';
    $('create-invite').disabled = !packageAvailable;
    if (status.agentsEnabled) await refreshDevices();
    else $('devices').replaceChildren();
    $('events').replaceChildren(...events.map((event) => {
      const item = document.createElement('li');
      const text = document.createElement('span');
      text.textContent = eventLabel(event.action) + (event.actor ? ` · ${adminLabels.get(event.actor) || event.actor.slice(0,8)}` : '');
      const time = document.createElement('time');
      time.dateTime = event.time;
      time.textContent = new Date(event.time).toLocaleString();
      item.append(text, time);
      return item;
    }));
  }
}

function refreshAdmins(admins){
  $('admins').replaceChildren(...admins.map(admin=>{
    const row=document.createElement('li');row.className='device-row';
    const detail=document.createElement('div');const name=document.createElement('strong');name.textContent=admin.name;
    const info=document.createElement('p');info.textContent=admin.revokedAt?'Revoked':`${admin.passkeys} ${admin.passkeys===1?'passkey':'passkeys'}`;
    detail.append(name,info);row.append(detail);
    if(!admin.revokedAt && admin.id!==currentAdminID){
      const revoke=document.createElement('button');revoke.className='quiet danger';revoke.textContent='Revoke access';
      revoke.addEventListener('click',()=>{if(confirm(`Revoke ${admin.name}'s console access? Their active sessions and tools will close.`))perform(()=>api(`/api/admins/${encodeURIComponent(admin.id)}/revoke`,{}));});
      row.append(revoke);
    }
    return row;
  }));
}

async function perform(action) {
  if (busy) return;
  busy = true;
  $('message').textContent = '';
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try { await action(); await refresh(); }
  catch (error) { $('message').textContent = error.name === 'NotAllowedError' ? 'Passkey request cancelled or not approved. Try again when ready.' : error.message; }
  finally { busy = false; for (const button of document.querySelectorAll('button')) button.disabled = false; $('create-invite').disabled = !packageAvailable; $('copy-replace-command').disabled=!packageAvailable; }
}

async function refreshDevices() {
  const devices = await api('/api/devices');
  deviceLabels = new Map(devices.map(device=>[device.id,device.name]));
  $('online-count').textContent = `${devices.filter(d=>d.online && !d.revoked).length} online`;
  $('pending-count').textContent = `${devices.filter(d=>d.pending && !d.revoked).length} awaiting approval`;
  const total = devices.filter(d=>!d.revoked).length;
  $('total-count').textContent = `${total} ${total === 1 ? 'device' : 'devices'}`;
  if (typeof selectedDevice !== 'undefined' && selectedDevice) {
    const current=devices.find(d=>d.id===selectedDevice.id);
    if (!current || !current.online || current.revoked) { closeSupport(); showPage('agents'); }
    else selectedDevice=current;
  }
  const visible = devices.filter(device => !device.revoked || $('show-revoked').checked);
  if (!visible.length) {
    const empty = document.createElement('li'); empty.className='empty-state';
    empty.textContent = devices.length ? 'No agents in use. Select Show revoked to view previous devices.' : 'No agents yet. Share the public instructions to connect a Windows PC.';
    $('devices').replaceChildren(empty); return;
  }
  const ordered=visible.sort((a,b)=>Number(b.pending)-Number(a.pending)||Number(b.online)-Number(a.online)||a.name.localeCompare(b.name));
  $('devices').replaceChildren(...ordered.map(device => {
    const row = document.createElement('li'); row.className = 'device-row';
    const description = document.createElement('div'); description.className='device-description';
    const name = document.createElement('strong'); name.textContent = device.name;
    const info = document.createElement('p');
    info.className = 'device-status ' + (device.revoked ? 'revoked' : device.pending ? 'pending' : device.online ? 'online' : 'offline');
    info.textContent = `${device.revoked ? 'Revoked' : device.pending ? 'Awaiting approval' : device.online ? 'Online' : 'Offline'} · ${device.mode} mode`;
    if (device.pending) info.textContent += ` · Requested ${new Date(device.created).toLocaleString()} · ${device.id.slice(0,8)}`;
    if (device.details) info.textContent += ` · ${device.details.hostname} · ${device.details.elevated ? 'Elevated' : 'Standard user'}`;
    description.append(name,info); row.append(description);
    if (!device.revoked) {
      const actions = document.createElement('div'); actions.className = 'device-actions';
      if (device.pending) {
        const approve=document.createElement('button');approve.textContent='Approve device';
        approve.addEventListener('click',()=>perform(()=>api(`/api/devices/${encodeURIComponent(device.id)}/approve`,{})));
        actions.append(approve);
      } else if (device.online) {
        const open = document.createElement('button'); open.className='open-agent';open.textContent='Open agent →';
        open.addEventListener('click',()=>openSupport(device)); actions.append(open);
        description.classList.add('clickable-agent');description.tabIndex=0;description.setAttribute('role','button');description.setAttribute('aria-label',`Open ${device.name}`);
        description.addEventListener('click',()=>openSupport(device));description.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();openSupport(device);}});
      }
      if (device.mode === 'temporary' && device.online) {
        const end = document.createElement('button'); end.className = 'quiet'; end.textContent = 'End session';
        end.addEventListener('click',() => perform(() => api(`/api/devices/${encodeURIComponent(device.id)}/disconnect`,{})));
        actions.append(end);
      }
      const revoke = document.createElement('button'); revoke.className = 'quiet danger'; revoke.textContent = device.pending ? 'Reject' : 'Revoke';
      revoke.addEventListener('click',() => {
        if (window.confirm(`${device.pending?'Reject':'Revoke access for'} ${device.name}? This device will need a new enrollment to connect.`)) perform(() => api(`/api/devices/${encodeURIComponent(device.id)}/revoke`,{}));
      });
      actions.append(revoke); row.append(actions);
    }
    return row;
  }));
}

$('device-mode').addEventListener('change',() => {
  $('mode-help').textContent = {
    user: 'Installs for the current user and starts at sign-in. No elevation prompt.',
    service: 'Run the command in an already elevated PowerShell. Installs a Windows service; it will not request elevation itself.',
    temporary: 'No automatic startup. The agent exits when its connection ends. Run the installed EXE again to allow another session.'
  }[$('device-mode').value];
});
$('create-invite').addEventListener('click',() => perform(async () => {
  const result = await api('/api/invites',{name:$('device-name').value,mode:$('device-mode').value});
  $('install-command').value = result.command;
  $('local-install-command').value = result.localCommand; $('replace-install-command').value = result.replaceCommand;
  $('support-link').value = result.supportURL;
  $('preview-link').href = result.supportURL;
  $('invite-expiry').textContent = `One device only. Enroll before ${new Date(result.expires).toLocaleString()}.`;
  $('installer').hidden = false;
}));
$('copy-link').addEventListener('click',() => perform(async () => {
  try {
    await navigator.clipboard.writeText($('support-link').value);
    $('message').textContent = 'Support link copied. Send it to your family member.';
  } catch {
    $('support-link').focus(); $('support-link').select();
    $('message').textContent = 'Press Ctrl+C (or Command+C) to copy the selected link.';
  }
}));
$('copy-command').addEventListener('click',() => perform(async () => {
  await navigator.clipboard.writeText($('install-command').value);
}));
$('copy-invite-replace').addEventListener('click',() => perform(async () => {await navigator.clipboard.writeText($('replace-install-command').value);}));
$('copy-replace-command').addEventListener('click',() => perform(async () => {
  const result=await api('/api/default-command');await navigator.clipboard.writeText(result.replaceCommand);$('message').textContent='Clean replacement command copied.';
}));
$('copy-local-command').addEventListener('click',() => perform(async () => {
  await navigator.clipboard.writeText($('local-install-command').value);
}));
$('refresh-devices').addEventListener('click',() => perform(refresh));
$('show-revoked').addEventListener('change',() => refreshDevices().catch(error => { $('message').textContent = error.message; }));

$('create-admin-invite').addEventListener('click',()=>perform(async()=>{
  const result=await api('/api/admins/invites',{name:$('admin-name').value});
  $('admin-invite-link').value=result.url;
  $('admin-invitation').hidden=false;
}));
$('copy-admin-invite').addEventListener('click',()=>perform(async()=>{await navigator.clipboard.writeText($('admin-invite-link').value);$('message').textContent='Private admin invitation copied.';}));
$('signin').addEventListener('click', () => perform(setupRequired || adminInvite ? register : login));
$('add-key').addEventListener('click', () => perform(register));
$('logout').addEventListener('click', () => perform(() => api('/api/logout', {})));
refresh().catch((error) => { $('message').textContent = error.message; });
