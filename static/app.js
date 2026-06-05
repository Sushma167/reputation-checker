// =====================================
// THEME
// =====================================

function toggleTheme() {

    const html = document.documentElement;

    const current =
        html.getAttribute("data-theme");

    const next =
        current === "dark"
        ? "light"
        : "dark";

    html.setAttribute(
        "data-theme",
        next
    );

    localStorage.setItem(
        "theme",
        next
    );
}

window.addEventListener("load", () => {

    const saved =
        localStorage.getItem("theme");

    if(saved){

        document.documentElement
            .setAttribute(
                "data-theme",
                saved
            );
    }
});

// =====================================
// LOADER
// =====================================

function loader(){

    return `
        <div style="padding:30px;text-align:center;">
            <div class="loader"></div>
        </div>
    `;
}

// =====================================
// DOMAIN CHECK
// =====================================

async function checkDomain(){

    const domain =
        document.getElementById(
            "domainInput"
        ).value.trim();

    if(!domain){

        alert(
            "Please enter a domain"
        );

        return;
    }

    const output =
        document.getElementById(
            "domainResult"
        );

    output.innerHTML =
        loader();

    try{

        const response =
            await fetch(
                `/api/domain/${domain}`
            );

        const data =
            await response.json();

        let mxRows = "";

        if(
            data.mx &&
            data.mx.length > 0
        ){

            data.mx.forEach(mx=>{

                mxRows += `
                <tr>
                    <td>${mx.priority}</td>
                    <td>${mx.host}</td>
                </tr>
                `;
            });

        }else{

            mxRows = `
            <tr>
                <td colspan="2">
                    No MX records found
                </td>
            </tr>
            `;
        }

        output.innerHTML = `

        <div class="result-card">

            <h3>SPF Record</h3>

            <div class="record">
                ${data.spf}
            </div>

        </div>

        <div class="result-card">

            <h3>DMARC Record</h3>

            <div class="record">
                ${data.dmarc}
            </div>

        </div>

        <div class="result-card">

            <h3>MX Records</h3>

            <table>

                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Host</th>
                    </tr>
                </thead>

                <tbody>
                    ${mxRows}
                </tbody>

            </table>

        </div>

        `;

    }catch(error){

        output.innerHTML = `

        <div class="result-card">

            Unable to retrieve domain information

        </div>

        `;
    }
}

// =====================================
// STATUS BADGE
// =====================================

function getBadge(status){

    if(status === "LISTED"){

        return `
        <span class="badge-listed">
            LISTED
        </span>
        `;
    }

    if(status === "CLEAN"){

        return `
        <span class="badge-clean">
            CLEAN
        </span>
        `;
    }

    return `
    <span class="badge-warning">
        UNKNOWN
    </span>
    `;
}

// =====================================
// SINGLE IP CHECK
// =====================================

async function checkIP(){

    const ip =
        document.getElementById(
            "ipInput"
        ).value.trim();

    if(!ip){

        alert(
            "Please enter an IP address"
        );

        return;
    }

    const output =
        document.getElementById(
            "ipResult"
        );

    output.innerHTML =
        loader();

    try{

        const response =
            await fetch(
                `/api/ip/${ip}`
            );

        const data =
            await response.json();

        output.innerHTML = `

        <div class="result-card">

            <h3>IP Address</h3>

            <div class="record">
                ${data.ip}
            </div>

        </div>

        <div class="result-card">

            <h3>Spamhaus</h3>

            ${getBadge(data.spamhaus)}

        </div>

        <div class="result-card">

            <h3>Spamcop</h3>

            ${getBadge(data.spamcop)}

        </div>

        <div class="result-card">

            <h3>Barracuda</h3>

            ${getBadge(data.barracuda)}

        </div>

        <div class="result-card">

            <h3>Overall Reputation</h3>

            ${getBadge(data.overall)}

        </div>

        `;

    }catch(error){

        output.innerHTML = `

        <div class="result-card">

            Failed to check IP reputation

        </div>

        `;
    }
}

// =====================================
// BULK CHECK
// =====================================

async function checkBulk(){

    const cidr =
        document.getElementById(
            "bulkInput"
        ).value.trim();

    if(!cidr){

        alert(
            "Please enter a CIDR range"
        );

        return;
    }

    const output =
        document.getElementById(
            "bulkResult"
        );

    output.innerHTML =
        loader();

    try{

        const response =
            await fetch(
                `/api/bulk?cidr=${encodeURIComponent(cidr)}`
            );

        const data =
            await response.json();

        if(data.detail){

            output.innerHTML = `

            <div class="result-card">

                ${data.detail}

            </div>

            `;

            return;
        }

        let rows = "";

        data.results.forEach(item=>{

            rows += `

            <tr>

                <td>${item.ip}</td>

                <td>
                    ${getBadge(item.spamhaus)}
                </td>

                <td>
                    ${getBadge(item.spamcop)}
                </td>

                <td>
                    ${getBadge(item.barracuda)}
                </td>

                <td>
                    ${getBadge(item.overall)}
                </td>

            </tr>

            `;
        });

        output.innerHTML = `

        <div class="result-card">

            <h3>
                CIDR Range:
                ${data.cidr}
            </h3>

            <p>
                Total IPs:
                ${data.total}
            </p>

            <table>

                <thead>

                    <tr>

                        <th>IP</th>

                        <th>Spamhaus</th>

                        <th>Spamcop</th>

                        <th>Barracuda</th>

                        <th>Overall</th>

                    </tr>

                </thead>

                <tbody>

                    ${rows}

                </tbody>

            </table>

        </div>

        `;

    }catch(error){

        output.innerHTML = `

        <div class="result-card">

            Bulk scan failed

        </div>

        `;
    }
}
