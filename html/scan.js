function timeout(ms, promise) {
    return new Promise(function (resolve, reject) {
        setTimeout(function () {
            reject(new Error("timeout"))
        }, ms)
        promise.then(resolve, reject)
    })
}

function scan(targetdata) {
    let sendDate = new Date().getTime();
    timeout(3000, fetch(`http://${targetdata.address}:${targetdata.port}/`, {
            mode: 'no-cors'
        }))
        .then(function (response) {
            let receiveDate = new Date().getTime();
            let result = {
                "error": false,
                "start": sendDate,
                "end": receiveDate,
                "duration": (receiveDate - sendDate),
                "target": targetdata
            };
            postMessage(result);
        })
        .catch(function (e) {
            let receiveDate = (new Date()).getTime();
            let result = {
                "error": true,
                "start": sendDate,
                "end": receiveDate,
                "duration": (receiveDate - sendDate),
                "target": targetdata
            };
            postMessage(result);
        })

}

onmessage = function (target) {
 //   console.log(`Worker: Message received from main script: ${target.data.address}:${target.data.port}`);
    scan(target.data);
 //   console.log('Worker: Posting message back to main script');

}
