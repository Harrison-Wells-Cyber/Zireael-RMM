'use strict';
(() => {
  const field = document.getElementById('help-command');
  const button = document.getElementById('copy-help-command');
  const notice = document.getElementById('link-notice');
  const status = document.getElementById('copy-status');
  let defaultCommand = '';
  let expires = 0;
  let timer;
  window.addEventListener('hashchange', () => window.location.reload());

  function showDefault(message = '') {
    clearInterval(timer);
    expires = 0;
    field.value = defaultCommand;
    button.disabled = !defaultCommand;
    button.textContent = 'Copy command';
    document.getElementById('link-expiry').textContent = 'Default installation · approval required';
    notice.hidden = !message;
    notice.classList.toggle('error', !!message);
    notice.textContent = message;
  }
  button.addEventListener('click', async () => {
    if (expires && Date.now() >= expires) showDefault('Your personal link has expired. The default command is still available below.');
    if (!field.value) return;
    try {
      await navigator.clipboard.writeText(field.value);
      button.textContent = 'Copied ✓';
      status.textContent = 'Now right-click in PowerShell to paste, then press Enter.';
    } catch {
      field.focus(); field.select();
      status.textContent = 'Press Ctrl+C to copy the selected command, then right-click in PowerShell to paste.';
    }
  });
  async function load() {
    try {
      const response = await fetch('/api/default-command', {cache:'no-store', credentials:'omit'});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Installer unavailable');
      defaultCommand = result.command;
      document.getElementById('platform').textContent = result.architecture === 'arm64' ? 'For Windows on ARM PCs' : 'For Windows x64 PCs';
      showDefault();
    } catch {
      showDefault('The installer is unavailable. Ask your helper to check the server.');
    }
    const match = /^#invite=([A-Za-z0-9_-]{43})$/.exec(window.location.hash);
    if (!match) {
      if (window.location.hash) showDefault('This personal support link is invalid. You can use the default command below.');
      return;
    }
    try {
      const response = await fetch('/api/support-invite', {
        method:'POST', credentials:'omit', cache:'no-store',
        headers:{'Content-Type':'application/json','X-RMM-Request':'1'},
        body:JSON.stringify({token:match[1]}), signal:AbortSignal.timeout(15000)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Personal support link unavailable.');
      expires = new Date(result.expires).getTime();
      if (Date.now() >= expires) throw new Error('Your personal support link has expired.');
      field.value = result.command;
      button.disabled = false;
      notice.hidden = true;
      document.getElementById('link-expiry').textContent = 'Use before ' + new Date(expires).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'}) + ' · One computer';
      timer = setInterval(() => { if (Date.now() >= expires) showDefault('Your personal link has expired. The default command is still available below.'); }, 1000);
      if (result.mode === 'service') {
        document.getElementById('open-instructions').textContent = 'Click Start and type PowerShell. Right-click Windows PowerShell, choose Run as administrator, and approve the Windows prompt.';
        document.getElementById('privilege-note').textContent = 'Your helper selected an installation that requires administrator access.';
        document.getElementById('availability').textContent = 'The support app runs as a Windows service. Your helper can reconnect while this computer is on and online, even before you sign in.';
      } else if (result.mode === 'temporary') {
        document.getElementById('availability').textContent = 'This is a temporary session. Access ends when your helper ends the session or the connection is lost. The app will not start automatically when you sign in.';
      }
    } catch (error) { showDefault(error.message + ' You can use the default command below.'); }
  }
  load();
})();
