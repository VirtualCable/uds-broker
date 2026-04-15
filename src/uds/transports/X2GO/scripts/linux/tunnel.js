'use strict';
import { Process, Tasks, Logger, File } from 'runtime';

const executablePath = Process.findExecutable('x2goclient');

if (!executablePath) {
    Logger.error('No X2GO client (x2goclient) found on system');
    throw new Error(
        '<p>You must have installed latest X2GO Client in order to connect to this UDS service.</p>\n<p>Please, install the required packages for your platform</p>'
    );
}
const tunnel = await Tasks.startTunnel({
    addr: data.tunnel.host,
    port: data.tunnel.port,
    ticket: data.tunnel.ticket,
    startup_time_ms: data.tunnel.startup_time,
    check_certificate: data.tunnel.verify_ssl,
    shared_secret: data.shared_secret,
});

const keyFile = File.createTempFile(File.getHomeDirectory(), data.key, '.key');
Tasks.addEarlyUnlinkableFile(keyFile);

const home = File.getHomeDirectory() + ':1;/media:1;';
const sessionConf = data.xf
    .replace('{export}', home)
    .replace('{keyFile}', keyFile.replace(/\\/g, '/'))
    .replace('{ip}', '127.0.0.1')
    .replace('{port}', String(tunnel.port));

const sessionFile = File.createTempFile(File.getHomeDirectory(), sessionConf, '.conf');
Tasks.addEarlyUnlinkableFile(sessionFile);

const process = Process.launch(executablePath, [
    `--session-conf=${sessionFile}`,
    '--session=UDS/connect',
    '--close-disconnect',
    '--hide',
    '--no-menu',
    '--add-to-known-hosts',
]);
Tasks.addWaitableApp(process);
