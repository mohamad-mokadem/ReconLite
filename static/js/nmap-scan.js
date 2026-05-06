// Nmap Scan JavaScript - Dedicated Nmap NSE + Vulners Integration
// Global variables
let currentNmapData = null;
let nmapScanInProgress = false;
let nmapCapabilities = { available: false };

// DOM Elements
const nmapForm = document.getElementById('nmapForm');
const nmapTargetInput = document.getElementById('nmapTarget');
const enableNseCheckbox = document.getElementById('enableNse');
const portRangeSelect = document.getElementById('portRange');
const nmapProgressSection = document.getElementById('nmapProgress');
const nmapResultsSection = document.getElementById('nmapResults');

// API Helper Function
async function makeNmapApiCall(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Nmap API call failed:', error);
        throw error;
    }
}

// Initialize Nmap Application
document.addEventListener('DOMContentLoaded', () => {
    console.log('🎯 Nmap Scanner initializing...');

    initializeNmapEventListeners();
    checkNmapCapabilities();
    loadTargetFromURL();
    updateNmapStatus('Ready');

    console.log('✅ Nmap Scanner ready');
});

// Event Listeners
function initializeNmapEventListeners() {
    if (nmapForm) {
        nmapForm.addEventListener('submit', handleNmapScanSubmit);
    }

    if (enableNseCheckbox) {
        enableNseCheckbox.addEventListener('change', updateNmapPreview);
    }

    if (portRangeSelect) {
        portRangeSelect.addEventListener('change', updateNmapPreview);
    }
}

// Check Nmap Capabilities
async function checkNmapCapabilities() {
    try {
        showNmapLoadingMessage('Checking Nmap capabilities...');

        const status = await makeNmapApiCall('/api/integration-status');

        nmapCapabilities.available = status.integrations?.enhanced_nmap?.enabled || false;
        nmapCapabilities.vulners = status.integrations?.vulners_cve_detection?.enabled || false;
        nmapCapabilities.nse_scripts = status.integrations?.enhanced_nmap?.nse_scripts || [];

        console.log('🎯 Nmap capabilities:', nmapCapabilities);

        updateNmapUI();
        updateNmapPreview();

    } catch (error) {
        console.warn('⚠️ Nmap capability check failed:', error);
        nmapCapabilities.available = false;
        showNmapNotification('Nmap capabilities limited - check installation', 'warning');
        updateNmapUI();
    } finally {
        hideNmapLoadingMessage();
    }
}

// Update Nmap UI based on capabilities
function updateNmapUI() {
    if (enableNseCheckbox) {
        enableNseCheckbox.disabled = !nmapCapabilities.available;
        enableNseCheckbox.checked = nmapCapabilities.available;

        if (!nmapCapabilities.available) {
            const optionGroup = enableNseCheckbox.closest('.option-group');
            if (optionGroup) optionGroup.classList.add('disabled');
        }
    }

    // Update capability indicators
    const nmapStatus = document.getElementById('nmapCapabilityStatus');
    if (nmapStatus) {
        nmapStatus.textContent = nmapCapabilities.available ? '✅ Nmap NSE Available' : '❌ Nmap Not Available';
        nmapStatus.className = nmapCapabilities.available ? 'status-good' : 'status-error';
    }

    const vulnersStatus = document.getElementById('vulnersCapabilityStatus');
    if (vulnersStatus) {
        vulnersStatus.textContent = nmapCapabilities.vulners ? '🛡️ Vulners API Configured' : '❌ Vulners Not Configured';
        vulnersStatus.className = nmapCapabilities.vulners ? 'status-good' : 'status-warning';
    }
}

// Update Nmap scan preview
function updateNmapPreview() {
    const nseEnabled = enableNseCheckbox?.checked && nmapCapabilities.available;
    const selectedRange = portRangeSelect?.value || '1-1000';
    const vulnersEnabled = nmapCapabilities.vulners && nseEnabled;

    // Update preview sections
    const previewNse = document.getElementById('previewNse');
    const previewVulners = document.getElementById('previewVulners');
    const previewTiming = document.getElementById('previewTiming');

    if (previewNse) {
        const status = previewNse.querySelector('.preview-icon');
        const text = previewNse.querySelector('.preview-text');

        if (status && text) {
            if (nseEnabled) {
                status.textContent = '✅';
                text.textContent = 'Enhanced NSE Script Discovery';
                previewNse.classList.remove('disabled');
            } else {
                status.textContent = '❌';
                text.textContent = 'Basic Port Discovery Only';
                previewNse.classList.add('disabled');
            }
        }
    }

    if (previewVulners) {
        const status = previewVulners.querySelector('.preview-icon');
        const text = previewVulners.querySelector('.preview-text');

        if (status && text) {
            if (vulnersEnabled) {
                status.textContent = '✅';
                text.textContent = 'Vulners CVE Detection';
                previewVulners.classList.remove('disabled');
            } else {
                status.textContent = '❌';
                text.textContent = 'No CVE Detection';
                previewVulners.classList.add('disabled');
            }
        }
    }

    if (previewTiming) {
        const status = previewTiming.querySelector('.preview-icon');
        const text = previewTiming.querySelector('.preview-text');

        if (status && text) {
            let estimatedTime = getNmapTimeEstimate(selectedRange, nseEnabled, vulnersEnabled);
            status.textContent = '⏱️';
            text.textContent = `Estimated Time: ${estimatedTime}`;
        }
    }
}

// Get Nmap time estimate
function getNmapTimeEstimate(portRange, nseEnabled, vulnersEnabled) {
    const ranges = {
        '1-100': { base: 2, nse: 3, vulners: 2 },
        '1-1000': { base: 5, nse: 8, vulners: 5 },
        '1-5000': { base: 15, nse: 20, vulners: 10 },
        '1-65535': { base: 30, nse: 45, vulners: 20 }
    };

    const range = ranges[portRange] || ranges['1-1000'];
    let time = range.base;

    if (nseEnabled) time += range.nse;
    if (vulnersEnabled) time += range.vulners;

    if (time <= 5) return `${time} minutes`;
    if (time <= 15) return `${time}-${time + 5} minutes`;
    return `${time}-${time + 10} minutes`;
}

// Load target from URL parameter
function loadTargetFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const target = urlParams.get('target');

    if (target && nmapTargetInput) {
        nmapTargetInput.value = decodeURIComponent(target);
        console.log('🎯 Loaded target from URL:', target);
    }
}

// Handle Nmap form submission
async function handleNmapScanSubmit(e) {
    e.preventDefault();

    if (nmapScanInProgress) {
        showNmapNotification('Nmap scan already in progress', 'warning');
        return;
    }

    const target = nmapTargetInput?.value?.trim();
    if (!target) {
        showNmapError('Please enter a valid target');
        return;
    }

    await startNmapScan(target);
}

// Start Nmap scan
async function startNmapScan(target) {
    nmapScanInProgress = true;
    updateNmapStatus('Scanning');
    hideNmapError();
    clearNmapResults();

    // Show progress section
    if (nmapResultsSection) nmapResultsSection.classList.add('hidden');
    if (nmapProgressSection) nmapProgressSection.classList.remove('hidden');

    // Initialize progress
    updateNmapProgress(0, 'Initializing Nmap scan...');

    try {
        const payload = {
            target: target,
            port_range: portRangeSelect?.value || '1-1000',
            enable_vulners: enableNseCheckbox?.checked && nmapCapabilities.available,
            scan_type: 'discovery',
            scan_timing: 'T3',
            enable_os_detection: false
        };

        console.log('🎯 Starting Nmap scan with config:', payload);

        // Start Nmap scan
        updateNmapProgress(10, 'Starting Nmap discovery...');

        const data = await makeNmapApiCall('/api/nmap-scan', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        if (data.error) {
            throw new Error(data.error);
        }

        // Simulate progress updates
        updateNmapProgress(30, 'Port discovery in progress...');
        await sleep(2000);
        updateNmapProgress(60, 'NSE scripts running...');
        await sleep(1500);
        updateNmapProgress(80, 'Vulnerability detection...');
        await sleep(1000);
        updateNmapProgress(100, 'Nmap scan complete!');

        // Store and display results
        currentNmapData = data;
        displayNmapResults(data);

        updateNmapStatus('Ready');
        showNmapNotification('Nmap scan completed successfully!', 'success');

    } catch (error) {
        console.error('❌ Nmap scan failed:', error);
        showNmapError(error.message || 'Nmap scan failed');
        updateNmapStatus('Error');

        if (nmapProgressSection) nmapProgressSection.classList.add('hidden');
    } finally {
        nmapScanInProgress = false;
    }
}

// Display Nmap results
function displayNmapResults(data) {
    console.log('📊 Displaying Nmap results:', data);

    // Hide progress, show results
    if (nmapProgressSection) nmapProgressSection.classList.add('hidden');
    if (nmapResultsSection) nmapResultsSection.classList.remove('hidden');

    // Create results content
    const resultsContent = document.getElementById('nmapResultsContent') || createNmapResultsContent();

    // Process nmap results
    const nmapResults = data.nmap_results || {};
    const discoveredPorts = nmapResults.discovered_ports || [];
    const vulnerabilities = nmapResults.vulnerabilities || [];
    const cveVulnerabilities = nmapResults.cve_vulnerabilities || [];
    const metadata = nmapResults.metadata || {};

    // Update summary cards
    updateNmapSummaryCards(discoveredPorts, vulnerabilities, cveVulnerabilities);

    // Display detailed results
    displayNmapPorts(discoveredPorts);
    displayNmapVulnerabilities(vulnerabilities, cveVulnerabilities);
    displayNmapMetadata(metadata, data);

    // Scroll to results
    if (nmapResultsSection) {
        nmapResultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Create results content structure
function createNmapResultsContent() {
    const resultsSection = nmapResultsSection;
    if (!resultsSection) return null;

    resultsSection.innerHTML = `
        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="summary-card">
                <div class="card-header">
                    <span class="card-icon">🔍</span>
                    <span class="card-label">Open Ports</span>
                </div>
                <div class="card-value" id="nmapPortCount">0</div>
            </div>
            <div class="summary-card">
                <div class="card-header">
                    <span class="card-icon">🛡️</span>
                    <span class="card-label">Vulnerabilities</span>
                </div>
                <div class="card-value" id="nmapVulnCount">0</div>
            </div>
            <div class="summary-card">
                <div class="card-header">
                    <span class="card-icon">⚡</span>
                    <span class="card-label">NSE Scripts</span>
                </div>
                <div class="card-value" id="nmapNseCount">0</div>
            </div>
            <div class="summary-card">
                <div class="card-header">
                    <span class="card-icon">🎯</span>
                    <span class="card-label">CVE Findings</span>
                </div>
                <div class="card-value" id="nmapCveCount">0</div>
            </div>
        </div>

        <!-- Detailed Results -->
        <div class="results-content">
            <!-- Discovered Ports -->
            <div class="result-panel">
                <div class="panel-header">
                    <h3 class="panel-title">🔍 Discovered Ports & Services</h3>
                    <button class="btn btn-small" onclick="exportNmapData('ports')">Export</button>
                </div>
                <div class="panel-content" id="nmapPortsResults">
                    <!-- Dynamic content -->
                </div>
            </div>

            <!-- Vulnerabilities -->
            <div class="result-panel" id="nmapVulnerabilitiesPanel">
                <div class="panel-header">
                    <h3 class="panel-title">🛡️ Security Vulnerabilities</h3>
                    <button class="btn btn-small" onclick="exportNmapData('vulnerabilities')">Export</button>
                </div>
                <div class="panel-content">
                    <div class="vuln-section">
                        <h4>NSE Script Findings</h4>
                        <div id="nmapVulnerabilityResults">
                            <!-- Dynamic content -->
                        </div>
                    </div>
                    <div class="vuln-section" id="nmapCveSection">
                        <h4>CVE Vulnerabilities (Vulners)</h4>
                        <div id="nmapCveResults">
                            <!-- Dynamic content -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- Scan Metadata -->
            <div class="result-panel">
                <div class="panel-header">
                    <h3 class="panel-title">⚙️ Nmap Scan Details</h3>
                </div>
                <div class="panel-content">
                    <div id="nmapMetadataResults">
                        <!-- Dynamic content -->
                    </div>
                </div>
            </div>
        </div>

        <!-- Action Bar -->
        <div class="action-bar">
            <button class="btn btn-secondary" onclick="newNmapScan()">
                <span class="btn-icon">🔄</span>
                New Nmap Scan
            </button>
            <button class="btn btn-primary" onclick="exportNmapFullReport()">
                <span class="btn-icon">📄</span>
                Export Report
            </button>
            <button class="btn btn-info" onclick="window.location.href='/active-scan'">
                <span class="btn-icon">⚡</span>
                Active Scan
            </button>
        </div>
    `;

    return document.getElementById('nmapResultsContent');
}

// Update summary cards
function updateNmapSummaryCards(ports, vulnerabilities, cveVulnerabilities) {
    animateNmapCounter('nmapPortCount', ports.length);
    animateNmapCounter('nmapVulnCount', vulnerabilities.length);
    animateNmapCounter('nmapCveCount', cveVulnerabilities.length);

    // Count NSE scripts used
    const nseScriptsUsed = new Set();
    vulnerabilities.forEach(vuln => {
        if (vuln.script) nseScriptsUsed.add(vuln.script);
    });
    animateNmapCounter('nmapNseCount', nseScriptsUsed.size);
}

// Display Nmap ports
function displayNmapPorts(ports) {
    const container = document.getElementById('nmapPortsResults');
    if (!container) return;

    if (!ports.length) {
        container.innerHTML = '<div class="empty-state">No open ports discovered</div>';
        return;
    }

    const html = ports.map(port => `
        <div class="port-entry">
            <div class="port-info">
                <span class="port-badge">${port.port}/${port.protocol || 'tcp'}</span>
                <div class="service-details">
                    <span class="service-name">${port.service || 'unknown'}</span>
                    ${port.version ? `<span class="service-version"> - ${port.version}</span>` : ''}
                    ${port.product ? `<span class="service-product"> (${port.product})</span>` : ''}
                </div>
                <span class="port-state ${port.state || 'open'}">${(port.state || 'open').toUpperCase()}</span>
            </div>
            ${port.banner ? `<div class="extra-info"><strong>Banner:</strong> ${escapeHtml(port.banner)}</div>` : ''}
            ${port.script_results?.length ? `<div class="extra-info"><strong>NSE Scripts:</strong> ${port.script_results.length} results</div>` : ''}
            ${port.cpe?.length ? `<div class="extra-info"><strong>CPE:</strong> ${port.cpe.join(', ')}</div>` : ''}
            ${port.extrainfo ? `<div class="extra-info"><strong>Extra Info:</strong> ${escapeHtml(port.extrainfo)}</div>` : ''}
        </div>
    `).join('');

    container.innerHTML = html;
}

// Display Nmap vulnerabilities
function displayNmapVulnerabilities(vulnerabilities, cveVulnerabilities) {
    // NSE Script vulnerabilities
    const vulnContainer = document.getElementById('nmapVulnerabilityResults');
    if (vulnContainer) {
        if (!vulnerabilities.length) {
            vulnContainer.innerHTML = '<div class="empty-state">No vulnerabilities found by NSE scripts</div>';
        } else {
            const html = vulnerabilities.map(vuln => `
                <div class="vuln-item ${vuln.severity?.toLowerCase() || 'info'}">
                    <span class="vuln-severity">${vuln.severity || 'Info'}</span>
                    <span class="vuln-title">${escapeHtml(vuln.title || vuln.id || 'NSE Finding')}</span>
                    ${vuln.description ? `<div class="vuln-description">${escapeHtml(vuln.description)}</div>` : ''}
                    ${vuln.script ? `<div class="vuln-source">NSE Script: ${escapeHtml(vuln.script)}</div>` : ''}
                </div>
            `).join('');
            vulnContainer.innerHTML = html;
        }
    }

    // CVE vulnerabilities from Vulners
    const cveContainer = document.getElementById('nmapCveResults');
    if (cveContainer) {
        if (!cveVulnerabilities.length) {
            cveContainer.innerHTML = '<div class="empty-state">No CVE vulnerabilities detected</div>';
        } else {
            const html = cveVulnerabilities.map(cve => `
                <div class="cve-item ${cve.severity?.toLowerCase() || 'info'}">
                    <div class="cve-header">
                        <span class="cve-id">${cve.cve_id || cve.id || 'Unknown'}</span>
                        <span class="cve-severity">${cve.severity || 'Info'}</span>
                        ${cve.cvss_score ? `<span class="cvss-score">CVSS: ${cve.cvss_score}</span>` : ''}
                    </div>
                    <div class="cve-title">${escapeHtml(cve.title || 'CVE Vulnerability')}</div>
                    ${cve.description ? `<div class="cve-description">${escapeHtml(cve.description.substring(0, 300))}${cve.description.length > 300 ? '...' : ''}</div>` : ''}
                    ${cve.href ? `<div class="cve-links"><a href="${cve.href}" target="_blank" rel="noopener">View Details</a></div>` : ''}
                    ${cve.recommendation ? `<div class="cve-recommendation"><strong>Recommendation:</strong> ${escapeHtml(cve.recommendation)}</div>` : ''}
                    <div class="cve-source">Source: Vulners API via Nmap NSE</div>
                </div>
            `).join('');
            cveContainer.innerHTML = html;
        }
    }
}

// Display Nmap metadata
function displayNmapMetadata(metadata, scanData) {
    const container = document.getElementById('nmapMetadataResults');
    if (!container) return;

    let html = '<div class="metadata-grid">';

    // Scan information
    html += `<div class="metadata-item"><strong>Target:</strong> ${escapeHtml(scanData.target || 'Unknown')}</div>`;
    html += `<div class="metadata-item"><strong>Port Range:</strong> ${escapeHtml(scanData.port_range || 'Unknown')}</div>`;
    html += `<div class="metadata-item"><strong>Scan Duration:</strong> ${scanData.scan_duration || 'Unknown'}s</div>`;

    // Nmap specific metadata
    if (scanData.vulners_enabled) {
        html += '<div class="metadata-item"><strong>Vulners Integration:</strong> ✅ Enabled</div>';
    }

    if (metadata.nmap_version) {
        html += `<div class="metadata-item"><strong>Nmap Version:</strong> ${escapeHtml(metadata.nmap_version)}</div>`;
    }

    if (metadata.scan_stats) {
        const stats = metadata.scan_stats;
        if (stats.hosts_up !== undefined) {
            html += `<div class="metadata-item"><strong>Hosts Up:</strong> ${stats.hosts_up}</div>`;
        }
        if (stats.hosts_scanned !== undefined) {
            html += `<div class="metadata-item"><strong>Hosts Scanned:</strong> ${stats.hosts_scanned}</div>`;
        }
    }

    if (metadata.scripts_run) {
        html += `<div class="metadata-item"><strong>NSE Scripts Run:</strong> ${metadata.scripts_run.length}</div>`;
    }

    html += '</div>';

    // Additional scan details
    if (scanData.nmap_results) {
        const results = scanData.nmap_results;
        html += `
            <div class="scan-summary">
                <h4>Scan Summary</h4>
                <div class="summary-grid">
                    <div class="summary-item"><strong>Open Ports:</strong> ${results.discovered_ports?.length || 0}</div>
                    <div class="summary-item"><strong>NSE Vulnerabilities:</strong> ${results.vulnerabilities?.length || 0}</div>
                    <div class="summary-item"><strong>CVE Findings:</strong> ${results.cve_vulnerabilities?.length || 0}</div>
                    <div class="summary-item"><strong>Scan Method:</strong> Enhanced Nmap NSE</div>
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

// Progress and status functions
function updateNmapProgress(percentage, message) {
    const progressFill = document.querySelector('#nmapProgress .progress-fill');
    const progressText = document.querySelector('#nmapProgress .progress-text');
    const progressPercentage = document.querySelector('#nmapProgress .progress-percentage');

    if (progressFill) progressFill.style.width = `${percentage}%`;
    if (progressText) progressText.textContent = message;
    if (progressPercentage) progressPercentage.textContent = `${percentage}%`;

    updateNmapProgressSteps(percentage);
}

function updateNmapProgressSteps(percentage) {
    const steps = document.querySelectorAll('#nmapProgress .step');
    const stepMap = [
        { step: 'input', threshold: 10 },
        { step: 'discovery', threshold: 40 },
        { step: 'nse', threshold: 70 },
        { step: 'complete', threshold: 100 }
    ];

    steps.forEach(step => {
        const stepData = stepMap.find(s => s.step === step.dataset.step);
        if (stepData && percentage >= stepData.threshold) {
            step.classList.add('completed');
            step.classList.remove('active');

            const icon = step.querySelector('.step-icon');
            if (icon) icon.textContent = '✓';
        }
    });
}

function updateNmapStatus(status) {
    const statusElements = document.querySelectorAll('.nmap-status-text');
    statusElements.forEach(el => {
        if (el) el.textContent = status;
    });
}

// Utility functions
function animateNmapCounter(elementId, target) {
    const element = document.getElementById(elementId);
    if (!element) return;

    let current = 0;
    const step = Math.max(1, target / 20);
    const timer = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 50);
}

function showNmapError(message) {
    console.error('Nmap Error:', message);
    showNmapNotification(message, 'error');
}

function hideNmapError() {
    // Hide any visible error toasts
    const errorToasts = document.querySelectorAll('.toast-error');
    errorToasts.forEach(toast => toast.classList.add('hidden'));
}

function showNmapNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span>${escapeHtml(message)}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;

    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };

    notification.style.cssText = `
        position: fixed;
        top: 2rem;
        right: 2rem;
        z-index: 1001;
        padding: 1rem;
        border-radius: 8px;
        color: white;
        background: ${colors[type] || colors.info};
        min-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function showNmapLoadingMessage(message) {
    updateNmapStatus(message);
}

function hideNmapLoadingMessage() {
    updateNmapStatus('Ready');
}

function clearNmapResults() {
    currentNmapData = null;

    // Clear result containers
    const containers = [
        'nmapPortsResults', 'nmapVulnerabilityResults', 'nmapCveResults', 'nmapMetadataResults'
    ];

    containers.forEach(id => {
        const container = document.getElementById(id);
        if (container) container.innerHTML = '';
    });

    // Reset summary cards
    ['nmapPortCount', 'nmapVulnCount', 'nmapNseCount', 'nmapCveCount'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.textContent = '0';
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Export functions
function newNmapScan() {
    if (nmapScanInProgress) {
        showNmapNotification('Cannot start new scan while one is in progress', 'warning');
        return;
    }

    if (nmapTargetInput) nmapTargetInput.value = '';
    clearNmapResults();

    if (nmapResultsSection) nmapResultsSection.classList.add('hidden');
    if (nmapProgressSection) nmapProgressSection.classList.add('hidden');

    updateNmapStatus('Ready');

    if (nmapTargetInput) nmapTargetInput.focus();
}

function exportNmapData(type) {
    if (!currentNmapData) {
        showNmapNotification('No Nmap data to export', 'error');
        return;
    }

    let data = '';
    const timestamp = new Date().toISOString().slice(0, 10);
    let filename = `nmap_${type}_${timestamp}`;

    const nmapResults = currentNmapData.nmap_results || {};

    switch (type) {
        case 'ports':
            const ports = nmapResults.discovered_ports || [];
            data = ports.map(p =>
                `${currentNmapData.target}\t${p.port}\t${p.protocol || 'tcp'}\t${p.service || 'unknown'}\t${p.version || ''}\t${p.state || 'open'}`
            ).join('\n');
            filename += '.tsv';
            break;

        case 'vulnerabilities':
            const allVulns = [
                ...(nmapResults.vulnerabilities || []),
                ...(nmapResults.cve_vulnerabilities || [])
            ];
            data = allVulns.map(vuln =>
                `${vuln.cve_id || vuln.id || 'N/A'}\t${vuln.severity || 'Unknown'}\t${vuln.title || 'N/A'}\t${vuln.cvss_score || 'N/A'}\t${vuln.source || 'Nmap'}`
            ).join('\n');
            filename += '.tsv';
            break;

        default:
            data = JSON.stringify(currentNmapData, null, 2);
            filename = `nmap_full_${timestamp}.json`;
    }

    if (!data) {
        showNmapNotification(`No ${type} data available to export`, 'warning');
        return;
    }

    downloadNmapFile(data, filename);
    showNmapNotification(`${type.charAt(0).toUpperCase() + type.slice(1)} data exported successfully`, 'success');
}

function exportNmapFullReport() {
    if (!currentNmapData) {
        showNmapNotification('No Nmap scan data available for export', 'error');
        return;
    }
    exportNmapData('full');
}

function downloadNmapFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideNmapError();
    }

    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        if (nmapForm && !nmapScanInProgress) {
            nmapForm.dispatchEvent(new Event('submit'));
        }
    }

    if (e.ctrlKey && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        newNmapScan();
    }

    if (e.ctrlKey && e.key.toLowerCase() === 'e') {
        e.preventDefault();
        if (currentNmapData) {
            exportNmapFullReport();
        }
    }
});

// Global error handlers
window.addEventListener('error', (event) => {
    console.error('Nmap interface error:', event.error);
    if (nmapScanInProgress) {
        nmapScanInProgress = false;
        updateNmapStatus('Error');
        showNmapError('An unexpected error occurred during Nmap scanning');
        if (nmapProgressSection) nmapProgressSection.classList.add('hidden');
    }
});

// Make functions globally available
window.newNmapScan = newNmapScan;
window.exportNmapData = exportNmapData;
window.exportNmapFullReport = exportNmapFullReport;

console.log('🎯 Nmap Scanner JavaScript loaded and ready!');