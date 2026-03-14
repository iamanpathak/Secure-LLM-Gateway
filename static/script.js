Chart.register(ChartDataLabels); 
let pieChart;
let entitiesCount = 0;

let allLogsData = [];
let showAllLogs = false;

let tempPieData = JSON.parse(localStorage.getItem('savedPieData'));
if (!tempPieData || tempPieData.length < 7) { tempPieData = [0, 0, 0, 0, 0, 0, 0]; }
let storedPieData = tempPieData;

let storedHeatmapData = JSON.parse(localStorage.getItem('savedHeatmapData')) || [];

function togglePasswordVisibility() {
    const pwdInput = document.getElementById('password');
    const eyeIcon = document.getElementById('eyeIcon');
    
    if (pwdInput.type === 'password') {
        pwdInput.type = 'text';
        eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
        eyeIcon.style.color = '#fff';
    } else {
        pwdInput.type = 'password';
        eyeIcon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
        eyeIcon.style.color = '#94a3b8';
    }
}

let authToken = localStorage.getItem('gateway_token');

window.onload = () => { 
    if (authToken) {
        showDashboard();
    }
};

async function performLogin() {
    const u = document.getElementById('username').value;
    const p = document.getElementById('password').value;
    
    const params = new URLSearchParams();
    params.append('username', u);
    params.append('password', p);

    try {
        const res = await fetch('/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params
        });

        if (res.ok) {
            const data = await res.json();
            authToken = data.access_token;
            localStorage.setItem('gateway_token', authToken);
            document.getElementById('loginError').style.display = 'none';
            showDashboard();
        } else {
            document.getElementById('loginError').style.display = 'block';
        }
    } catch (e) { console.log(e); }
}

function logout() {
    localStorage.removeItem('gateway_token');
    authToken = null;
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('pdf-export-area').style.display = 'none';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
}

function showDashboard() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('pdf-export-area').style.display = 'block';
    initChat(); initPieChart(); initHeatmap(); loadHistory();
}

async function fetchWithAuth(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['Authorization'] = 'Bearer ' + authToken;
    
    const res = await fetch(url, options);
    if (res.status === 401) { 
        logout();
        alert("Session expired. Please login again.");
        throw new Error("Unauthorized");
    }
    return res;
}

function initChat() {
    const chatbox = document.getElementById('chatbox');
    chatbox.innerHTML = localStorage.getItem('chatHistory') || "";
    chatbox.scrollTop = chatbox.scrollHeight;
}

function initPieChart() {
    if(pieChart) return; 
    const ctx = document.getElementById('threadPieChart').getContext('2d');
    
    const chartColors = ['#94a3b8', '#c084fc', '#fbbf24', '#4ade80', '#818cf8', '#f87171', '#ff0000'];

    pieChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Phone', 'Email', 'Name', 'Address', 'Cards', 'Govt IDs', 'Injections'],
            datasets: [{
                data: storedPieData, 
                backgroundColor: chartColors,
                hoverBackgroundColor: chartColors,
                borderColor: '#111827', 
                borderWidth: 2,
                hoverOffset: 4 
            }]
        },
        options: {
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 20, font: { size: 11 } } },
                datalabels: {
                    color: '#fff',
                    font: { weight: 'bold', size: 14 },
                    formatter: (value) => value > 0 ? value : '' 
                }
            },
            maintainAspectRatio: false
        }
    });
}

function initHeatmap() {
    const container = document.getElementById('heatmapContainer');
    container.innerHTML = "";
    storedHeatmapData.forEach(pos => {
        const p = document.createElement('div');
        p.className = 'heat-point';
        p.title = `Source: Web Client | Severity: ${pos.score || 30}% | Status: Intercepted | Date: ${pos.date || 'N/A'} | Time: ${pos.time || 'N/A'}`;
        p.style.cursor = 'pointer';
        p.style.left = pos.left;
        p.style.top = pos.top;
        container.appendChild(p);
    });
}

function getRiskDetails(originalText, maskedText) {
    let riskLevel = "SECURE"; 
    let riskColor = "#86efac";

    let highRegex = /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,16}\b|\b[a-zA-Z]{5}[0-9]{4}[a-zA-Z]{1}\b|\b\d{12}\b|\b\d{4}\s\d{4}\s\d{4}\b|(?:ignore all|forget all|bypass|do anything now|\bdan\b|system prompt|jailbreak)/i;
    let medRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i;
    let phoneRegex = /\b\d{10}\b/;
    let addrRegex = /(?:Street|St|Road|Rd|Avenue|Ave|Marg|Vihar|Nagar|Enclave|Sector|Phase|Block|Area|City|Village|State|County|Providence|Province|Country)\b/i;

    let hasHigh = highRegex.test(originalText) || maskedText.includes("CARD") || maskedText.includes("PAN") || maskedText.includes("AADHAAR") || maskedText.includes("PROMPT_INJECTION");
    let hasMed = medRegex.test(originalText) || phoneRegex.test(originalText) || addrRegex.test(originalText) || maskedText.includes("EMAIL") || maskedText.includes("PHONE") || maskedText.includes("ADDRESS") || maskedText.includes("NAME");

    if (!hasMed && !hasHigh) {
        let name1 = /\b(?:my name is|i am|i\'m|this is|call me|name is|it is|it was|it\'s)\s+[a-zA-Z]+/i.test(originalText);
        let name2 = /\b[A-Z][a-z]+\s[A-Z][a-z]+\b/.test(originalText);
        if (name1 || name2) hasMed = true;
    }

    if (hasHigh) {
        riskLevel = "HIGH"; riskColor = "#f87171";
    } else if (hasMed) {
        riskLevel = "MEDIUM"; riskColor = "#fbbf24";
    }

    if (riskLevel !== "SECURE" && originalText === maskedText) {
        riskLevel += " (UNMASKED)";
    }

    return { level: riskLevel, color: riskColor };
}

function downloadPDF() {
    window.scrollTo(0, 0); 
    const tbody = document.querySelector('#historyTable tbody');
    const logsToShow = allLogsData.slice(0, 10);
    
    tbody.innerHTML = logsToShow.map(row => {
        const riskData = getRiskDetails(row[1], row[2]);
        return `<tr><td><span class="blurred-text" onclick="this.classList.toggle('unblur')">${row[1]}</span></td><td class="tag">${row[2].replace(/</g, "&lt;")}</td><td><b style="color:${riskData.color}">${riskData.level}</b></td><td>${row[3]}</td><td style="color:#64748b; font-size:0.8em;">${row[4]}</td></tr>`;
    }).join('');
    
    const element = document.getElementById('pdf-export-area');
    const opt = { margin: 10, filename: 'Secure_Gateway_Executive_Report.pdf', image: { type: 'jpeg', quality: 1 }, html2canvas: { scale: 2, useCORS: true, backgroundColor: '#0d1117', scrollY: 0, windowY: 0 }, jsPDF: { unit: 'mm', format: 'a3', orientation: 'portrait' } };
    setTimeout(() => { html2pdf().set(opt).from(element).save().then(() => { renderTable(); }); }, 100);
}

async function sendMessage() {
    const input = document.getElementById('userInput');
    const text = input.value.trim();
    if(!text) return;
    const maskOptions = { name: document.getElementById('maskName').checked, phone: document.getElementById('maskPhone').checked, email: document.getElementById('maskEmail').checked, address: document.getElementById('maskAddress').checked, card: document.getElementById('maskCard').checked };
    const chatbox = document.getElementById('chatbox');
    chatbox.innerHTML += `<div class="user-msg">${text}</div>`;
    localStorage.setItem('chatHistory', chatbox.innerHTML);
    input.value = '';
    try {
        const response = await fetchWithAuth('/ask', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ text: text, options: maskOptions }) });
        const data = await response.json();
        chatbox.innerHTML += `<div class="ai-msg">${data.ai_answer}</div>`;
        chatbox.scrollTop = chatbox.scrollHeight;
        localStorage.setItem('chatHistory', chatbox.innerHTML);
        if(data.entity_count) {
            entitiesCount += data.entity_count;
            document.getElementById('entities-detected').innerText = entitiesCount;
            let govtCount = 0; let emailCount = 0; let phoneCount = 0; let addressCount = 0; let cardCount = 0; let injectionCount = 0;
            
            const injectionRegex = /\b(?:ignore all the previous instructions|forget all the previous instructions|ignore all previous instructions|forget all previous instructions|bypass|do anything now|dan|system prompt|jailbreak)\b/gi;
            const injectionMatches = text.match(injectionRegex);
            if(injectionMatches) injectionCount += injectionMatches.length;
            
            const panMatches = text.match(/\b[a-zA-Z]{5}[0-9]{4}[a-zA-Z]{1}\b/g);
            const aadhaarMatches = text.match(/\b\d{12}\b/g) || text.match(/\b\d{4}\s\d{4}\s\d{4}\b/g);
            if (panMatches) govtCount += panMatches.length;
            if (aadhaarMatches) govtCount += aadhaarMatches.length;

            if (maskOptions.email) {
                const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
                if (emailMatches) emailCount += emailMatches.length;
            }
            
            if (maskOptions.phone) {
                const phoneMatches = text.match(/\b\d{10}\b/g);
                if (phoneMatches) phoneCount += phoneMatches.length;
            }
            
            if (maskOptions.address) {
                const addressRegex = /\b(?:\d{1,5}[a-zA-Z]?\s*[,\-]?\s*)?(?:(?!(?:my|address|is|are|was|were|live|at|in|on|and)\b)[a-zA-Z0-9.,-]+\s+){0,3}(?:Street|St|Road|Rd|Avenue|Ave|Marg|Vihar|Nagar|Enclave|Sector|Phase|Block|Area|City|Village|State|County|Providence|Province|Country)\b(?:\s+(?!(?:my|address|is|are|was|were|live|at|in|on|and)\b)[a-zA-Z0-9.,-]+){0,3}/gi;
                if(text.match(addressRegex)) {
                    let tempAddrText = text.replace(addressRegex, "<ADDRESS>");
                    tempAddrText = tempAddrText.replace(/(?:<ADDRESS>[\s,]*)+/g, "<ADDRESS> ");
                    let finalAddrMatches = tempAddrText.match(/<ADDRESS>/g);
                    if(finalAddrMatches) addressCount += finalAddrMatches.length;
                }
            }

            if (maskOptions.card) {
                const cardMatches = text.match(/\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,16}\b/g);
                if(cardMatches) cardCount += cardMatches.length;
            }

            pieChart.data.datasets[0].data[6] += injectionCount; 
            pieChart.data.datasets[0].data[5] += govtCount; 
            pieChart.data.datasets[0].data[4] += cardCount; 
            pieChart.data.datasets[0].data[3] += addressCount; 
            pieChart.data.datasets[0].data[1] += emailCount; 
            pieChart.data.datasets[0].data[0] += phoneCount; 
            
            let totalFoundRegex = govtCount + emailCount + phoneCount + addressCount + cardCount + injectionCount;
            
            // STRICT FIX: Only update name pie chart if name checkbox is TICKED
            if (maskOptions.name && data.entity_count > totalFoundRegex) { 
                pieChart.data.datasets[0].data[2] += (data.entity_count - totalFoundRegex); 
            }
            
            pieChart.update();
            localStorage.setItem('savedPieData', JSON.stringify(pieChart.data.datasets[0].data));
        }
        if(data.risk_score > 0) addHeatPoint(data.risk_score);
        loadHistory();
    } catch (err) { console.error(err); }
}

function addHeatPoint(riskScore) {
    const container = document.getElementById('heatmapContainer');
    const p = document.createElement('div');
    p.className = 'heat-point';
    const now = new Date();
    const currentDate = now.toLocaleDateString(); 
    const currentTime = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0') + ':' + now.getSeconds().toString().padStart(2, '0');
    p.title = `Source: Web Client | Severity: ${riskScore}% | Status: Intercepted | Date: ${currentDate} | Time: ${currentTime}`;
    p.style.cursor = 'pointer';
    const leftPos = Math.random() * 90 + '%'; const topPos = Math.random() * 80 + '%';
    p.style.left = leftPos; p.style.top = topPos; container.appendChild(p);
    storedHeatmapData.push({left: leftPos, top: topPos, score: riskScore, time: currentTime, date: currentDate});
    if(storedHeatmapData.length > 20) { storedHeatmapData.shift(); if(container.firstChild) container.removeChild(container.firstChild); }
    localStorage.setItem('savedHeatmapData', JSON.stringify(storedHeatmapData));
}

async function loadHistory() {
    try {
        const res = await fetchWithAuth('/history');
        const data = await res.json();
        const res_an = await fetchWithAuth('/analytics');
        const data_an = await res_an.json();
        document.getElementById('total-msgs').innerText = data_an.total;
        document.getElementById('threats-blocked').innerText = data_an.leaks;
        allLogsData = data.history; renderTable();
    } catch (e) { console.log("History Load Error:", e); }
}

function renderTable() {
    const tbody = document.querySelector('#historyTable tbody');
    const btn = document.getElementById('seeMoreBtn');
    const logsToShow = showAllLogs ? allLogsData : allLogsData.slice(0, 8);
    
    tbody.innerHTML = logsToShow.map(row => {
        const riskData = getRiskDetails(row[1], row[2]);
        return `<tr><td><span class="blurred-text" onclick="this.classList.toggle('unblur')">${row[1]}</span></td><td class="tag">${row[2].replace(/</g, "&lt;")}</td><td><b style="color:${riskData.color}">${riskData.level}</b></td><td>${row[3]}</td><td style="color:#64748b; font-size:0.8em;">${row[4]}</td></tr>`;
    }).join('');
    
    if (allLogsData.length > 8) { btn.style.display = "inline-block"; btn.innerText = showAllLogs ? "Show Less ▲" : "See More ▼"; } else { btn.style.display = "none"; }
}

function toggleLogs() { showAllLogs = !showAllLogs; renderTable(); }

async function uploadFile() {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => { document.getElementById('userInput').value = e.target.result; sendMessage(); };
    reader.readAsText(file);
}

function clearHeatmap() { if(confirm("Are you sure?")) { storedHeatmapData = []; localStorage.setItem('savedHeatmapData', JSON.stringify(storedHeatmapData)); document.getElementById('heatmapContainer').innerHTML = ""; } }

function clearPieChart() { if(confirm("Are you sure?")) { pieChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0, 0]; pieChart.update(); localStorage.setItem('savedPieData', JSON.stringify([0, 0, 0, 0, 0, 0, 0])); } }

async function clearEverything() {
    if(confirm("Are you sure?")) {
        await fetchWithAuth('/clear', { method: 'DELETE' });
        document.getElementById('chatbox').innerHTML = ""; localStorage.removeItem('chatHistory');
        entitiesCount = 0; document.getElementById('entities-detected').innerText = "0";
        document.getElementById('total-msgs').innerText = "0"; document.getElementById('threats-blocked').innerText = "0";
        allLogsData = []; showAllLogs = false; renderTable();
    }
}

async function exportCSV() { 
    try {
        const res = await fetchWithAuth('/export-csv');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a'); a.style.display = 'none'; a.href = url; a.download = 'security_logs.csv';
        document.body.appendChild(a); a.click(); window.URL.revokeObjectURL(url);
    } catch (e) { console.log("Export failed:", e); }
}