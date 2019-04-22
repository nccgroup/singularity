function timeout(ms, promise,controller) {
    return new Promise(function (resolve, reject) {
        setTimeout(function () {
            controller.abort();
            reject(new Error("timeout"))
        }, ms)
        promise.then(resolve, reject)
    })
}

function scan(targetdata, duration) {
    let sendDate = new Date().getTime();
    var controller = new AbortController();//NO IE support
    var signal = controller.signal;
    timeout(duration, fetch(`http://${targetdata.address}:${targetdata.port}/`, {
            mode: 'no-cors',
            credentials: 'omit',
            signal
        }),controller)
        .then(function (response) {
            let receiveDate = new Date().getTime();
            let result = {
                "error": false,
                "errorReason": null,
                "start": sendDate,
                "end": receiveDate,
                "duration": (receiveDate - sendDate),
                "target": targetdata
            };
            postMessage(result);
        })
        .catch(function (e) {
            let receiveDate = (new Date()).getTime();
            console.log(`Scanner: ${e.message} for ${targetdata.address}:${targetdata.port}.`);
            let result = {
                "error": true,
                "errorReason": e.message,
                "start": sendDate,
                "end": receiveDate,
                "duration": (receiveDate - sendDate),
                "target": targetdata
            };
            postMessage(result);
//            console.log(`Worker: Sending result: ${result.duration}`);
        })

}

onmessage = function (message) {
//    console.log(`Worker: Message received from main script: ${target.data.address}:${target.data.port}`);
    scan(message.data.targetdata, message.data.timeout);
 //   console.log('Worker: Posting message back to main script');

}
