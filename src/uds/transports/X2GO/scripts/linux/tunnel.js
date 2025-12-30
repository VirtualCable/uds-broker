"use strict";
import { Process, Tasks, Logger, Utils } from "runtime";

// "sp" is the JSON object received from UDS (to match Python naming)

// Same error message as Python (simple HTML)
const errorString =
    "<p>Could not connect to tunnel server.</p><p>Please, check your network settings.</p>";

// 1. Open tunnel (simulate Python's forward)
let fs = Process.tunnel({
    remote: [sp["tunHost"], parseInt(sp["tunPort"])],
    ticket: sp["ticket"],
    timeout: sp["tunWait"],
    check_certificate: sp["tunChk"],
});

// 2. Check that tunnel works
if (!fs.check()) {
    Logger.error("Could not connect to tunnel server");
    throw new Error(errorString);
}

// 3. Prepare home and key file
let home = Process.expandUser("~") + ":1;/media:1;";
let keyFile = Utils.saveTempFile(sp["key"]);
let theFile = Utils.expandVars(sp["xf"], {
    export: home,
    keyFile: keyFile.replace("\\", "/"),
    ip: "127.0.0.1",
    port: fs.server_address[1],
});
let filename = Utils.saveTempFile(theFile);

// 4. Find x2goclient
let executable = Utils.findApp
    ? Utils.findApp("x2goclient")
    : Process.findExecutable("x2goclient");
if (!executable) {
    Logger.error("x2goclient not found");
    throw new Error(
        "<p>You must have installed latest X2GO Client in order to connect to this UDS service.</p>\n<p>Please, install the required packages for your platform</p>"
    );
}

// 5. Launch x2goclient
let params = [
    `--session-conf=${filename}`,
    "--session=UDS/connect",
    "--close-disconnect",
    "--hide",
    "--no-menu",
    "--add-to-known-hosts",
];
Logger.debug(`Launching x2goclient: ${executable}`);
Logger.debug(`Parameters: ${JSON.stringify(params)}`);
let process = Process.launch(executable, params);
Tasks.addWaitableApp(process);
