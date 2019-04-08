// web worker

function flush(hostname, port, iterations) {
    const start = Math.ceil(Math.random() * 2 ** 32)
    const maxIter = start + iterations
    for (let i = start; i < maxIter; i++) {
        let url = `http://n${i}.${hostname}:${port}/`;
        fetch(url, {mode: 'no-cors'});
    };
}

onmessage = function (message) {
    flush(message.data.hostname, message.data.port, message.data.iterations);
}