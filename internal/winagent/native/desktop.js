// Original Zireael-RMM adapter, CC0. MeshAgent is used in standalone script mode.
// The only connection is to the parent Go agent's private, local named pipe.
var pipe = require('net').createConnection({path:process.argv[1]});
var desktop;
pipe.on('connect', function () {
    desktop = require('meshDesktop').getRemoteDesktopStream();
    if (!desktop) { process.exit(1); return; }
    desktop.on('error', function () { process.exit(1); });
    desktop.on('end', function () { process.exit(0); });
    // A fixed readiness marker precedes the native KVM bytes.
    pipe.write('RMMKVM1\n');
    desktop.pipe(pipe);
    pipe.pipe(desktop);
});
pipe.on('error', function () { process.exit(1); });
pipe.on('end', function () { process.exit(0); });
pipe.on('close', function () { process.exit(0); });
