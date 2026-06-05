// =====================================
// THEME SYSTEM
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

window.onload = () => {

    const saved =
        localStorage.getItem("theme");

    if(saved){

        document.documentElement
            .setAttribute(
                "data-theme",
                saved
            );
    }
};

// =====================================
// LOADER
// =====================================

function loader(){

    return `
    <div style="padding:30px;text-align:center">
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

        alert("Enter a domain");
        return;
    }

    const output =
        document.getElementById(
            "domainResult"
        );

    output.innerHTML =
        loader();

    try{

        const res =
            await fetch(
                `/api/domain/${domain}`
            );

        const data =
            await res.json();

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
                    No MX Records Found
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

    }catch(err){

        output.innerHTML = `

        <div class="result-card">

            Error retrieving domain data

        </div>

        `;
    }
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

        alert("Enter an IP");
        return;
    }

    const output =
        document.getElementById(
            "ipResult"
        );

    output.innerHTML =
        loader();

    try{

        const res =
            await fetch(
                `/api/ip/${ip}`
            );

        const data =
            await res.json();

        function badge(status){

            if(status==="LISTED"){

                return `
                <span class="badge-listed">
                    LISTED
                </span>
                `;
            }

            if(status==="CLEAN"){

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

        output.innerHTML = `

        <div class="result-card">

            <h3>IP Address</h3>

            <div class="record">
                ${data.ip}
            </div>

        </div>

        <div class="result-card">

            <h3>Spamhaus</h3>

            ${badge(data.spamhaus)}

        </div>

        <div class="result-card">

            <h3>Spamcop</h3>

            ${badge(data.spamcop)}

        </div>

        <div class="result-card">

            <h3>Barracuda</h3>

            ${badge(data.barracuda)}

        </div>

        <div class="result-card">

            <h3>Overall Status</h3>

            ${badge(data.overall)}

        </div>

        `;

    }catch(err){

        output.innerHTML = `

        <div class="result-card">

            Unable to check IP reputation

        </div>

        `;
    }
}

// =====================================
// BULK IP CHECK
// =====================================

async function checkBulk(){

    const cidr =
        document.getElementById(
            "bulkInput"
        ).value.trim();

    if(!cidr){

        alert(
            "Enter CIDR range"
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

        const res =
            await fetch(
                `/api/bulk?cidr=${encodeURIComponent(cidr)}`
            );

        const data =
            await res.json();

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

                <td>${item.spamhaus}</td>

                <td>${item.spamcop}</td>

                <td>${item.barracuda}</td>

                <td>${item.overall}</td>

            </tr>

            `;
        });

        output.innerHTML = `

        <div class="result-card">

            <h3>
                Range:
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

    }catch(err){

        output.innerHTML = `

        <div class="result-card">

            Bulk scan failed

        </div>

        `;
    }
}
