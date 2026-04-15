'use strict';
import { Process, Tasks, Logger, File } from 'runtime';

const errorString = `<p>You need to have installed virt-viewer to connect to this UDS service.</p>\n<p>Please, install appropriate package for your system. (probably named something like <b>virt-viewer</b>)</p>`;

const executable = Process.findExecutable('remote-viewer');
if (!executable) {
    Logger.error('No SPICE client (remote-viewer) found on system');
    throw new Error(errorString);
}

let theFile = data.as_file_ns;
let fs = null;
let fss = null;

if (data.ticket) {
    fs = await Tasks.startTunnel({
        addr: data.tunHost,
        port: data.tunPort,
        ticket: data.ticket,
        startup_time_ms: data.tunWait,
        check_certificate: data.tunChk,
    });
}

if (data.ticket_secure) {
    theFile = data.as_file;
    fss = await Tasks.startTunnel({
        addr: data.tunHost,
        port: data.tunPort,
        ticket: data.ticket_secure,
        startup_time_ms: data.tunWait,
        check_certificate: data.tunChk,
    });
}

theFile = theFile
    .replace('{secure_port}', fss ? fss.port : '-1')
    .replace('{port}', fs ? fs.port : '-1');

const filename = File.createTempFile(File.getHomeDirectory(), theFile, '.vv');
Tasks.addEarlyUnlinkableFile(filename);
Logger.debug(`Launching SPICE client (${executable}) with ${filename}`);
const process = Process.launch(executable, [filename]);
Tasks.addWaitableApp(process);
