'use strict';
import { Process, Tasks, Logger, File, Utils } from 'runtime';

const errorString = `You must have installed latest X2GO Client in order to connect to this UDS service.\nPlease, install the required packages for your platform.`;

const executablePath = Process.findExecutable('x2goclient');
if (!executablePath) {
    Logger.error('No X2GO client found on system');
    throw new Error(errorString);
}

const keyFile = File.createTempFile(File.getHomeDirectory(), data.key, '.key');
Tasks.addEarlyUnlinkableFile(keyFile);

const home = File.getHomeDirectory() + ':1;/media:1;';
const sessionConf = Utils.expandVars(
    data.xf
        .replace('{export}', home)
        .replace('{keyFile}', keyFile.replace(/\\/g, '/'))
        .replace('{ip}', data.ip)
        .replace('{port}', data.port)
        .replace('{login}', data.login)
);

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
