// Simple Passive Reconnaissance JavaScript - No Classes
'use strict';

// Global variables
let currentScanData = null;
let scanInProgress = false;

// DOM elements (initialized after DOM loads)
let elements = {};

// Supported ports for active scanning
const SUPPORTED_PORTS = [21, 22, 25, 161, 443, 445, 990];

// Service type mapping
const SERVICE_MAP = {
    21: 'FTP',
    22: 'SSH',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    135: 'RPC',
    139: 'NetBIOS',
    161: 'SNMP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S'
};

// Initialize DOM elements
function initializeElements() {
    elements = {
        reconForm: document.getElementById('reconForm'),
        targetInput: document.getElementById('targetInput'),
        progressSection: document.getElementById('progressSection'),
        resultsSection: document.getElementById('resultsSection'),
        errorNotification: document.getElementById('errorNotification'),
        successNotification: document.getElementById('successNotification'),

        // Progress elements
        progressMessage: document.querySelector('.progress-message'),
        progressPercent: document.querySelector('.progress-percent'),
        progressFill: document.querySelector('.progress-fill'),

        // Counter elements
        servicesCount: document.getElementById('servicesCount'),
        dnsCount: document.getElementById('dnsCount'),
        subdomainsCount: document.getElementById('subdomainsCount'),
        activeScanCount: document.getElementById('activeScanCount'),

        // Result containers
        servicesResults: document.getElementById('servicesResults'),
        dnsResults: document.getElementById('dnsResults'),
        subdomainsResults: document.getElementById('subdomainsResults'),
        whoisResults: document.getElementById('whoisResults'),
        summaryResults: document.getElementById('summaryResults'),

        // Action buttons
        bulkActiveScanBtn: document.getElementById('bulkActiveScanBtn')
    };
}

// Setup event listeners
function setupEventListeners() {
    if (elements.reconForm) {
        elements.reconForm.addEventListener('submit', handleReconSubmit);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'Enter' && !scanInProgress) {
            e.preventDefault();
            if (elements.reconForm) {
                elements.reconForm.dispatchEvent(new Event('submit'));
            }
        }

        if (e.key === 'Escape') {
            hideNotifications();
        }

        if (e.ctrlKey && e.key.toLowerCase() === 'n') {
            e.preventDefault();
            startNewRecon();
        }

        if (e.ctrlKey && e.key.toLowerCase() === 'e') {
            e.preventDefault();
            if (currentScanData) {
                exportFullReport();
            }
        }

        if (e.ctrlKey && e.key.toLowerCase() === 'a') {
            e.preventDefault();
            if (currentScanData) {
                launchBulkActiveScans();
            }
        }
    });
}

// Handle form submission
function handleReconSubmit(e) {
    e.preventDefault();

    if (scanInProgress) {
        showNotification('Reconnaissance already in progress', 'error');
        return;
    }

    const target = elements.targetInput ? elements.targetInput.value.trim() : '';
    if (!target) {
        showError('Please enter a valid target');
        return;
    }

    startReconnaissance(target);
}

// Start reconnaissance
async function startReconnaissance(target) {
    scanInProgress = true;
    updateStatus('Reconnaissance in Progress');
    hideNotifications();
    clearResults();

    console.log(`🚀 Starting passive reconnaissance for: ${target}`);

    // Show progress section
    showSection('progressSection');
    hideSection('resultsSection');

    try {
        // Update progress
        updateProgress(0, 'Initializing reconnaissance...');

        // Make API call with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 second timeout

        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorMessage;
            } catch (e) {
                // Use status text if JSON parsing fails
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        // Simulate progress updates
        await simulateProgress();

        // Store and display results
        currentScanData = data;
        displayResults(data);

        updateStatus('Ready for Reconnaissance');
        showNotification('Passive reconnaissance completed successfully', 'success');

    } catch (error) {
        console.error('❌ Reconnaissance failed:', error);

        if (error.name === 'AbortError') {
            showError('Request timeout - scan took too long');
        } else {
            showError(error.message || 'Reconnaissance failed');
        }

        updateStatus('Error');
        hideSection('progressSection');
    } finally {
        scanInProgress = false;
    }
}

// Simulate progress updates
async function simulateProgress() {
    const steps = [
        { progress: 25, message: 'Validating target...', step: 'validate' },
        { progress: 50, message: 'DNS intelligence gathering...', step: 'dns' },
        { progress: 75, message: 'Service discovery...', step: 'services' },
        { progress: 100, message: 'Analysis complete...', step: 'complete' }
    ];

    for (const step of steps) {
        updateProgress(step.progress, step.message);
        updateStepStatus(step.step, 'active');
        await sleep(800);
        updateStepStatus(step.step, 'completed');
    }
}

// Display results
function displayResults(data) {
    console.log('📊 Displaying reconnaissance results:', data);

    // Hide progress, show results
    hideSection('progressSection');
    showSection('resultsSection');

    // Update summary cards
    updateSummaryCards(data);

    // Display detailed results
    displayServices(data.ports_services || []);
    displayDNS(data.securitytrails_dns_records || []);
    displaySubdomains(data.subdomains || []);
    displayWhois(data.whois_info || {});
    displaySummary(data);

    // Scroll to results
    if (elements.resultsSection) {
        elements.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Update summary cards
function updateSummaryCards(data) {
    const services = data.ports_services || [];
    const activeScanReady = services.filter(s => isSupportedForActiveScan(s.port));

    const stats = {
        services: services.length,
        dns: data.securitytrails_dns_records ? data.securitytrails_dns_records.length : 0,
        subdomains: data.subdomains ? data.subdomains.length : 0,
        activeScan: activeScanReady.length
    };

    // Update counters with null checks
    Object.entries(stats).forEach(([key, value]) => {
        animateCounter(`${key}Count`, value);
    });

    // Show bulk active scan button if services available
    if (activeScanReady.length > 0 && elements.bulkActiveScanBtn) {
        elements.bulkActiveScanBtn.style.display = 'flex';
        const btnText = elements.bulkActiveScanBtn.querySelector('.btn-text');
        if (btnText) {
            btnText.textContent = `Launch Security Testing (${activeScanReady.length} services)`;
        }
    }
}

// Display services
function displayServices(services) {
    if (!elements.servicesResults) return;

    if (!services.length) {
        elements.servicesResults.innerHTML = createEmptyState(
            'No Services Discovered',
            'No open services were found during passive reconnaissance'
        );
        return;
    }

    const html = services.map(service => createServiceEntry(service)).join('');
    elements.servicesResults.innerHTML = html;
}

// Create service entry HTML
function createServiceEntry(service) {
    const isSupported = isSupportedForActiveScan(service.port);
    const serviceType = getServiceType(service.port);

    return `
        <div class="service-entry">
            <div class="service-header">
                <div class="service-info">
                    <div class="port-badge">
                        ${service.port}/${service.protocol || 'tcp'}
                    </div>
                    <div class="service-details">
                        <div class="service-name">${escapeHtml(service.service || serviceType)}</div>
                        ${service.version ? `<div class="service-version">${escapeHtml(service.version)}</div>` : ''}
                    </div>
                </div>
                ${isSupported ? `
                    <button class="active-scan-btn" 
                            onclick="launchActiveScanForService('${service.ip || 'unknown'}', ${service.port}, '${service.service || 'auto'}')"
                            title="Launch active security scan on this service">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                        </svg>
                        Active Scan
                    </button>
                ` : `
                    <div class="not-supported-badge">
                        <span>Passive Only</span>
                    </div>
                `}
            </div>
            
            ${renderServiceMeta(service)}
        </div>
    `;
}

// Render service metadata
function renderServiceMeta(service) {
    const metaItems = [];

    if (service.banner) {
        metaItems.push({
            label: 'Service Banner',
            value: service.banner.substring(0, 150) + (service.banner.length > 150 ? '...' : '')
        });
    }

    if (service.source) {
        metaItems.push({
            label: 'Discovery Source',
            value: service.source
        });
    }

    if (service.ip && currentScanData && service.ip !== currentScanData.target) {
        metaItems.push({
            label: 'IP Address',
            value: service.ip
        });
    }

    if (metaItems.length === 0) return '';

    return `
        <div class="service-meta">
            ${metaItems.map(item => `
                <div class="meta-item">
                    <div class="meta-label">${item.label}</div>
                    <div class="meta-value">${escapeHtml(item.value)}</div>
                </div>
            `).join('')}
        </div>
    `;
}

// Display DNS records
function displayDNS(records) {
    if (!elements.dnsResults) return;

    if (!records.length) {
        elements.dnsResults.innerHTML = createEmptyState(
            'No DNS Records Found',
            'No DNS records were discovered for this domain'
        );
        return;
    }

    const html = records.map(record => `
        <div class="dns-record">
            <div class="dns-type">${record.type || 'Unknown'}</div>
            <div class="dns-value">${escapeHtml(record.value || 'No value')}</div>
        </div>
    `).join('');

    elements.dnsResults.innerHTML = html;
}

// Display subdomains
function displaySubdomains(subdomains) {
    if (!elements.subdomainsResults) return;

    if (!subdomains.length) {
        elements.subdomainsResults.innerHTML = createEmptyState(
            'No Subdomains Found',
            'No subdomains were discovered through passive methods'
        );
        return;
    }

    const html = `
        <div class="subdomain-container">
            ${subdomains.map(subdomain => `
                <div class="subdomain-chip" onclick="copyToClipboard('${escapeHtml(subdomain)}')">
                    ${escapeHtml(subdomain)}
                </div>
            `).join('')}
        </div>
    `;

    elements.subdomainsResults.innerHTML = html;
}

// Display WHOIS information
function displayWhois(whoisData) {
    if (!elements.whoisResults) return;

    if (!Object.keys(whoisData).length) {
        elements.whoisResults.innerHTML = createEmptyState(
            'No WHOIS Data',
            'WHOIS information could not be retrieved for this domain'
        );
        return;
    }

    const html = `
        <div class="whois-grid">
            ${Object.entries(whoisData).map(([key, value]) => `
                <div class="whois-item">
                    <div class="whois-label">${formatWhoisLabel(key)}</div>
                    <div class="whois-value">${escapeHtml(value)}</div>
                </div>
            `).join('')}
        </div>
    `;

    elements.whoisResults.innerHTML = html;
}

// Display summary
function displaySummary(data) {
    if (!elements.summaryResults) return;

    const summary = {
        'Target': data.target || 'Unknown',
        'Scan Type': data.type === 'domain' ? 'Domain Reconnaissance' : 'IP Range Reconnaissance',
        'Services Found': data.ports_services ? data.ports_services.length : 0,
        'Discovery Methods': data.discovery_methods ? data.discovery_methods.join(', ') : 'Standard passive methods',
        'Scan Duration': formatDuration(data.scan_time),
        'Status': 'Completed Successfully'
    };

    const html = `
        <div class="summary-grid">
            ${Object.entries(summary).map(([key, value]) => `
                <div class="summary-item">
                    <div class="summary-label">${key}</div>
                    <div class="summary-value">${escapeHtml(String(value))}</div>
                </div>
            `).join('')}
        </div>
    `;

    elements.summaryResults.innerHTML = html;
}

// Utility functions
function isSupportedForActiveScan(port) {
    return SUPPORTED_PORTS.includes(parseInt(port));
}

function getServiceType(port) {
    return SERVICE_MAP[parseInt(port)] || 'Unknown';
}

function createEmptyState(title, subtitle) {
    return `
        <div class="empty-state">
            <div class="empty-icon">–</div>
            <div class="empty-title">${title}</div>
            <div class="empty-subtitle">${subtitle}</div>
        </div>
    `;
}

function formatWhoisLabel(key) {
    return key.replace(/_/g, ' ')
             .replace(/\b\w/g, l => l.toUpperCase());
}

function formatDuration(scanTime) {
    if (!scanTime) return 'Unknown';
    try {
        const date = new Date(scanTime);
        return date.toLocaleString();
    } catch {
        return scanTime;
    }
}

// Animate counter
function animateCounter(elementId, target) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.warn(`Element ${elementId} not found for counter animation`);
        return;
    }

    let current = 0;
    const increment = Math.max(1, Math.ceil(target / 30));
    const duration = 1000;
    const stepTime = duration / (target / increment);

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = current;
    }, stepTime);
}

// Update progress
function updateProgress(percentage, message) {
    if (elements.progressFill) {
        elements.progressFill.style.width = `${percentage}%`;
    }
    if (elements.progressMessage) {
        elements.progressMessage.textContent = message;
    }
    if (elements.progressPercent) {
        elements.progressPercent.textContent = `${percentage}%`;
    }
}

// Update step status
function updateStepStatus(stepName, status) {
    const step = document.querySelector(`[data-step="${stepName}"]`);
    if (!step) return;

    // Remove all status classes
    step.classList.remove('active', 'completed');

    if (status === 'active') {
        step.classList.add('active');
        const statusText = step.querySelector('.step-status');
        if (statusText) statusText.textContent = 'In Progress';
    } else if (status === 'completed') {
        step.classList.add('completed');
        const statusText = step.querySelector('.step-status');
        if (statusText) statusText.textContent = 'Completed';
    }
}

// Update status
function updateStatus(status) {
    const elements = document.querySelectorAll('.status-text');
    elements.forEach(el => {
        if (el) el.textContent = status;
    });
}

// Show/hide sections
function showSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.remove('hidden');
    }
}

function hideSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.add('hidden');
    }
}

// Notification functions
function showError(message) {
    console.error('❌ Error:', message);
    showNotification(message, 'error');
}

function showNotification(message, type = 'success') {
    const notificationId = type === 'error' ? 'errorNotification' : 'successNotification';
    const messageId = type === 'error' ? 'errorMessage' : 'successMessage';

    const notification = document.getElementById(notificationId);
    const messageEl = document.getElementById(messageId);

    if (notification && messageEl) {
        messageEl.textContent = message;
        notification.classList.remove('hidden');

        // Auto-hide after 5 seconds
        setTimeout(() => hideNotifications(), 5000);
    }
}

function hideNotifications() {
    const notifications = ['errorNotification', 'successNotification'];
    notifications.forEach(id => {
        const notification = document.getElementById(id);
        if (notification) {
            notification.classList.add('hidden');
        }
    });
}

// Clear results
function clearResults() {
    currentScanData = null;

    const containers = [
        'servicesResults', 'dnsResults', 'subdomainsResults',
        'whoisResults', 'summaryResults'
    ];

    containers.forEach(id => {
        const container = document.getElementById(id);
        if (container) container.innerHTML = '';
    });

    // Reset counters
    ['services', 'dns', 'subdomains', 'activeScan'].forEach(type => {
        const element = document.getElementById(`${type}Count`);
        if (element) element.textContent = '0';
    });

    // Hide bulk active scan button
    if (elements.bulkActiveScanBtn) {
        elements.bulkActiveScanBtn.style.display = 'none';
    }
}

// Utility functions
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
function exportServices() {
    if (!currentScanData) {
        showNotification('No services data to export', 'error');
        return;
    }

    const services = currentScanData.ports_services || [];
    if (services.length === 0) {
        showNotification('No services found to export', 'error');
        return;
    }

    const data = services.map(s =>
        `${s.ip || currentScanData.target}\t${s.port}\t${s.protocol || 'tcp'}\t${s.service || 'unknown'}\t${s.version || ''}`
    ).join('\n');

    const header = 'IP\tPort\tProtocol\tService\tVersion\n';
    const filename = `services_${new Date().toISOString().slice(0, 10)}.tsv`;

    downloadFile(header + data, filename);
    showNotification('Services exported successfully', 'success');
}

function exportDNS() {
    if (!currentScanData) {
        showNotification('No DNS data to export', 'error');
        return;
    }

    const records = currentScanData.securitytrails_dns_records || [];
    if (records.length === 0) {
        showNotification('No DNS records found to export', 'error');
        return;
    }

    const data = records.map(r =>
        `${r.type || 'Unknown'}\t${r.value || 'No value'}`
    ).join('\n');

    const header = 'Type\tValue\n';
    const filename = `dns_records_${new Date().toISOString().slice(0, 10)}.tsv`;

    downloadFile(header + data, filename);
    showNotification('DNS records exported successfully', 'success');
}

function exportSubdomains() {
    if (!currentScanData) {
        showNotification('No subdomains data to export', 'error');
        return;
    }

    const subdomains = currentScanData.subdomains || [];
    if (subdomains.length === 0) {
        showNotification('No subdomains found to export', 'error');
        return;
    }

    const data = subdomains.join('\n');
    const filename = `subdomains_${new Date().toISOString().slice(0, 10)}.txt`;

    downloadFile(data, filename);
    showNotification('Subdomains exported successfully', 'success');
}

function exportWhois() {
    if (!currentScanData) {
        showNotification('No WHOIS data to export', 'error');
        return;
    }

    const whois = currentScanData.whois_info || {};
    if (Object.keys(whois).length === 0) {
        showNotification('No WHOIS information found to export', 'error');
        return;
    }

    const data = Object.entries(whois).map(([key, value]) =>
        `${key.replace(/_/g, ' ')}: ${value}`
    ).join('\n');

    const filename = `whois_${new Date().toISOString().slice(0, 10)}.txt`;

    downloadFile(data, filename);
    showNotification('WHOIS data exported successfully', 'success');
}

function exportFullReport() {
    if (!currentScanData) {
        showNotification('No data to export', 'error');
        return;
    }

    const data = JSON.stringify(currentScanData, null, 2);
    const filename = `passive_recon_report_${new Date().toISOString().slice(0, 10)}.json`;

    downloadFile(data, filename);
    showNotification('Full report exported successfully', 'success');
}

// Action functions
function startNewRecon() {
    if (scanInProgress) {
        showNotification('Cannot start new reconnaissance while scan is in progress', 'error');
        return;
    }

    // Clear form and results
    if (elements.targetInput) {
        elements.targetInput.value = '';
        elements.targetInput.focus();
    }

    clearResults();
    hideSection('resultsSection');
    hideSection('progressSection');
    updateStatus('Ready for Reconnaissance');
    hideNotifications();
}

function launchActiveScanForService(ip, port, service) {
    const targetData = [{
        ip: ip,
        port: port,
        service: service
    }];

    // Store in session storage
    sessionStorage.setItem('pendingActiveScans', JSON.stringify(targetData));

    // Navigate to active scan page with single target flag
    window.location.href = '/active-scan?from=passive&single=true';
}

function launchBulkActiveScans() {
    if (!currentScanData || !currentScanData.ports_services) {
        showNotification('No scan data available for active scanning', 'error');
        return;
    }

    const services = currentScanData.ports_services || [];
    const supportedServices = services.filter(service =>
        isSupportedForActiveScan(service.port)
    );

    if (supportedServices.length === 0) {
        showNotification('No services support active scanning', 'error');
        return;
    }

    const activeTargets = supportedServices.map(service => ({
        ip: service.ip || currentScanData.target,
        port: service.port,
        service: service.service || 'auto'
    }));

    // Store targets in session storage
    sessionStorage.setItem('pendingActiveScans', JSON.stringify(activeTargets));

    // Navigate to active scan page
    window.location.href = '/active-scan?from=passive';
}

// File download helper
function downloadFile(content, filename) {
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

// Copy to clipboard
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard', 'success');
        }).catch(() => {
            showNotification('Copy failed', 'error');
        });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showNotification('Copied to clipboard', 'success');
        } catch (err) {
            showNotification('Copy failed', 'error');
        }
        document.body.removeChild(textArea);
    }
}

// Hide error/success notifications
function hideError() {
    const errorNotification = document.getElementById('errorNotification');
    if (errorNotification) {
        errorNotification.classList.add('hidden');
    }
}

function hideSuccess() {
    const successNotification = document.getElementById('successNotification');
    if (successNotification) {
        successNotification.classList.add('hidden');
    }
}

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('🎯 Initializing PassiveRecon...');

    initializeElements();
    setupEventListeners();
    updateStatus('Ready for Reconnaissance');

    console.log('🎯 PassiveRecon Professional initialized successfully');
    console.log('🚀 Keyboard shortcuts: Ctrl+Enter (scan), Ctrl+N (new), Ctrl+E (export), Ctrl+A (active scans)');
    console.log('🔧 Available functions: startNewRecon(), exportFullReport(), launchBulkActiveScans()');
});