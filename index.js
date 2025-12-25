let logData = [];
let analysis = {};
let fileName = '';

window.addEventListener('DOMContentLoaded', () => {
    loadFromCache();
});

function saveToCache() {
    const cacheData = {
        logData: logData,
        analysis: analysis,
        fileName: fileName,
        timestamp: new Date().toISOString()
    };
    try {
        const dataStr = JSON.stringify(cacheData);
        const chunks = [];
        const chunkSize = 1000000;
        
        for (let i = 0; i < dataStr.length; i += chunkSize) {
            chunks.push(dataStr.slice(i, i + chunkSize));
        }
        
        sessionStorage.setItem('logAnalyzerChunks', chunks.length.toString());
        chunks.forEach((chunk, index) => {
            sessionStorage.setItem(`logAnalyzerData_${index}`, chunk);
        });
        
        console.log('Data cached successfully');
    } catch (e) {
        console.error('Failed to cache data:', e);
        alert('Warning: Could not cache data. Data may be too large.');
    }
}

function loadFromCache() {
    try {
        const numChunks = parseInt(sessionStorage.getItem('logAnalyzerChunks') || '0');
        if (numChunks === 0) return;

        let dataStr = '';
        for (let i = 0; i < numChunks; i++) {
            dataStr += sessionStorage.getItem(`logAnalyzerData_${i}`) || '';
        }

        const cacheData = JSON.parse(dataStr);
        logData = cacheData.logData || [];
        analysis = cacheData.analysis || {};
        fileName = cacheData.fileName || '';

        if (logData.length > 0) {
            document.getElementById('fileName').textContent = `Loaded from cache: ${fileName} (${cacheData.timestamp})`;
            displayAnalysis();
            displayLogEntries();
            document.getElementById('analysisSection').classList.remove('hidden');
        }
    } catch (e) {
        console.error('Failed to load cache:', e);
    }
}

function clearCache() {
    if (confirm('Are you sure you want to clear cached data?')) {
        const numChunks = parseInt(sessionStorage.getItem('logAnalyzerChunks') || '0');
        for (let i = 0; i < numChunks; i++) {
            sessionStorage.removeItem(`logAnalyzerData_${i}`);
        }
        sessionStorage.removeItem('logAnalyzerChunks');
        
        logData = [];
        analysis = {};
        fileName = '';
        document.getElementById('fileName').textContent = '';
        document.getElementById('analysisSection').classList.add('hidden');
        alert('Cache cleared successfully!');
    }
}

document.getElementById('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    fileName = file.name;
    document.getElementById('fileName').textContent = `Loaded: ${fileName}`;

    const text = await file.text();
    const lines = text.split('\n').filter(line => line.trim());

    logData = parseLogFile(lines);
    analysis = analyzeLog(logData);
    
    displayAnalysis();
    displayLogEntries();
    
    document.getElementById('analysisSection').classList.remove('hidden');
    
    saveToCache();
});

function parseLogFile(lines) {
    return lines.map((line, idx) => {
        const entry = {
            id: idx,
            raw: line,
            timestamp: null,
            level: 'INFO',
            ip: null,
            user: null,
            message: line
        };

        const timestampPatterns = [
            /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/,
            /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/,
            /(\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*\])/
        ];
        
        for (const pattern of timestampPatterns) {
            const match = line.match(pattern);
            if (match) {
                entry.timestamp = match[1].replace(/[\[\]]/g, '');
                break;
            }
        }

        const levelMatch = line.match(/\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|TRACE)\b/i);
        if (levelMatch) {
            entry.level = levelMatch[1].toUpperCase();
        }

        const ipMatch = line.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
        if (ipMatch) {
            entry.ip = ipMatch[0];
        }

        const userMatch = line.match(/(?:user|username|login)[:\s]+([^\s,]+)/i);
        if (userMatch) {
            entry.user = userMatch[1];
        }

        const statusMatch = line.match(/\s(\d{3})\s/);
        if (statusMatch) {
            entry.status = statusMatch[1];
        }

        return entry;
    });
}

function analyzeLog(entries) {
    const stats = {
        total: entries.length,
        timeRange: { start: null, end: null },
        levels: {},
        ips: {},
        users: {},
        errors: [],
        suspiciousActivities: []
    };

    entries.forEach(entry => {
        stats.levels[entry.level] = (stats.levels[entry.level] || 0) + 1;

        if (entry.ip) {
            stats.ips[entry.ip] = (stats.ips[entry.ip] || 0) + 1;
        }

        if (entry.user) {
            stats.users[entry.user] = (stats.users[entry.user] || 0) + 1;
        }

        if (['ERROR', 'CRITICAL', 'FATAL'].includes(entry.level)) {
            stats.errors.push(entry);
        }

        if (entry.raw.match(/failed|unauthorized|denied|forbidden|attack|injection|malicious|breach|exploit/i)) {
            stats.suspiciousActivities.push(entry);
        }

        if (entry.timestamp) {
            if (!stats.timeRange.start) stats.timeRange.start = entry.timestamp;
            stats.timeRange.end = entry.timestamp;
        }
    });

    return stats;
}

function displayAnalysis() {
    document.getElementById('totalEntries').textContent = analysis.total;
    document.getElementById('errorCount').textContent = analysis.errors.length;
    document.getElementById('uniqueIPs').textContent = Object.keys(analysis.ips).length;
    document.getElementById('suspiciousCount').textContent = analysis.suspiciousActivities.length;

    const ipList = document.getElementById('ipList');
    ipList.innerHTML = Object.entries(analysis.ips)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => `
            <div class="list-item">
                <span class="ip-address" onclick="openIPInfo('${ip}')" title="Click to view IP info">${ip}</span>
                <span>${count} requests</span>
            </div>
        `).join('');

    const levelList = document.getElementById('levelList');
    levelList.innerHTML = Object.entries(analysis.levels)
        .sort((a, b) => b[1] - a[1])
        .map(([level, count]) => `
            <div class="list-item">
                <span class="level level-${level}">${level}</span>
                <span>${count} entries</span>
            </div>
        `).join('');

    if (analysis.suspiciousActivities.length > 0) {
        document.getElementById('suspiciousAlert').classList.remove('hidden');
        document.getElementById('suspiciousText').textContent = 
            `${analysis.suspiciousActivities.length} suspicious activities detected`;
        
        const suspiciousEntries = document.getElementById('suspiciousEntries');
        suspiciousEntries.innerHTML = analysis.suspiciousActivities
            .slice(0, 20)
            .map(entry => createLogEntryHTML(entry))
            .join('');
    }
}

function createLogEntryHTML(entry) {
    const ipHTML = entry.ip ? 
        `<span class="ip-address" onclick="openIPInfo('${entry.ip}')" title="Click to view IP info">${entry.ip}</span>` : 
        '';
    
    return `
        <div class="log-entry level-${entry.level}">
            ${entry.timestamp ? `<span class="timestamp">[${entry.timestamp}]</span>` : ''}
            <span class="level level-${entry.level}">${entry.level}</span>
            ${ipHTML}
            <span>${escapeHtml(entry.raw)}</span>
        </div>
    `;
}

function displayLogEntries() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const levelFilter = document.getElementById('levelFilter').value;

    const filtered = logData.filter(entry => {
        const matchesSearch = entry.raw.toLowerCase().includes(searchTerm);
        const matchesLevel = levelFilter === 'all' || entry.level === levelFilter;
        return matchesSearch && matchesLevel;
    });

    const logEntries = document.getElementById('logEntries');
    logEntries.innerHTML = filtered.map(entry => createLogEntryHTML(entry)).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function openIPInfo(ip) {
    window.open(`https://ipinfo.io/${ip}`, '_blank');
}

function exportReport() {
    const report = `DIGITAL FORENSIC LOG ANALYSIS REPORT
    
    =====================================
    File: ${fileName}
    Generated: ${new Date().toLocaleString()}

    SUMMARY
    -------
    Total Entries: ${analysis.total}
    Time Range: ${analysis.timeRange.start || 'N/A'} to ${analysis.timeRange.end || 'N/A'}

    LOG LEVELS
    ----------
    ${Object.entries(analysis.levels).map(([level, count]) => `${level}: ${count}`).join('\n')}

    TOP IP ADDRESSES
    ----------------
    ${Object.entries(analysis.ips).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, count]) => `${ip}: ${count} requests`).join('\n')}

    ERRORS DETECTED
    ---------------
    ${analysis.errors.length} error(s) found

    SUSPICIOUS ACTIVITIES
    --------------------
    ${analysis.suspiciousActivities.length} suspicious entries detected

    ${analysis.suspiciousActivities.slice(0, 20).map(entry => `[${entry.timestamp || 'No timestamp'}] ${entry.raw}`).join('\n')}
    `;

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_report_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

document.getElementById('searchInput').addEventListener('input', displayLogEntries);
document.getElementById('levelFilter').addEventListener('change', displayLogEntries);