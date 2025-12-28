'use strict';
import { Process, Tasks, Logger, File, Utils } from 'runtime';

// We receive data in "data" variable, which is an object from json readonly

const errorString = `You must have installed latest X2GO Client in order to connect to this UDS service.\nPlease, install the required packages for your platform.`;

// Try to find x2goclient executable
const executablePath = Process.findExecutable('x2goclient');

if (!executablePath) {
    Logger.error('No X2GO client found on system');
    throw new Error(errorString);
}

// Crear archivo temporal para la clave, igual que jrodriguez
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
Logger.debug('Session file created at: ' + sessionFile);
Logger.debug('Session file content: ' + sessionConf);
Tasks.addEarlyUnlinkableFile(sessionFile);

// Lanzar x2goclient con el archivo de sesión
const params = [
    `--session-conf=${sessionFile}`,
    '--session=UDS/connect',
    '--close-disconnect',
    '--hide',
    '--no-menu',
    '--add-to-known-hosts',
];
const process = Process.launch(executablePath, params);
Tasks.addWaitableApp(process);
