let nmapCapabilities = {
    available: false,
    nse_scripts: false,
    vulners_integration: false
};



// Global state management
let currentScanMode = 'manual';
let selectedTemplates = new Set();
let activeScanInProgress = false;
let scanProgressTracker = null;
let pendingTargets = [];
let currentScanData = null;
let importedTargetsData = null;
let aggressiveScanAvailable = false;

const SUPPORTED_PORTS = [21, 22, 25, 80, 161, 443, 445, 465, 587, 990, 2121, 2525, 8000, 8021, 8080, 8443, 9443];

// Utility functions
const Utils = {
    validateIP: function(ip) {
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipRegex.test(ip)) return false;
        return ip.split('.').every(part => {
            const num = parseInt(part);
            return num >= 0 && num <= 255;
        });
    },

    validatePort: function(port) {
        const portNum = parseInt(port);
        return portNum >= 1 && portNum <= 65535;
    },

    showNotification: function(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);

        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `notification ${type}`;
        toast.style.cssText = `
            position: fixed; top: 2rem; right: 2rem; 
            background: ${type === 'success' ? 'linear-gradient(135deg, #10b981, #059669)' : 
                        type === 'error' ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 
                        type === 'warning' ? 'linear-gradient(135deg, #f59e0b, #d97706)' : 
                        'linear-gradient(135deg, #3b82f6, #2563eb)'};
            color: white; padding: 1rem 1.5rem; border-radius: 12px; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            z-index: 1001; font-weight: 600; animation: slideIn 0.4s ease;
            max-width: 300px; font-family: 'Inter', sans-serif;
        `;
        toast.textContent = message;
        document.body.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 4000);
    },

    handleError: function(error, context = 'Operation') {
        console.error(`${context} error:`, error);
        this.showNotification(`${context} failed: ${error.message || error}`, 'error');
    },

    getServiceType: function(port) {
        const serviceMap = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            161: 'SNMP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            587: 'SMTP',
            990: 'FTPS',
            2121: 'FTP',
            2525: 'SMTP',
            8021: 'FTP'
        };
        return serviceMap[parseInt(port)] || 'Unknown';
    },

    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// Add slideIn animation CSS if not exists
if (!document.getElementById('slideInAnimation')) {
    const style = document.createElement('style');
    style.id = 'slideInAnimation';
    style.textContent = `
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(100%); }
            to { opacity: 1; transform: translateX(0); }
        }
    `;
    document.head.appendChild(style);
}

// DOM Ready initialization
document.addEventListener('DOMContentLoaded', function() {
    checkNmapCapabilities();
    console.log('Active Scan page loaded');
    initializeActiveScan();
});


const DEEP_SCAN_WARNINGS = {
    ftp: {
        title: "⚠️ AGGRESSIVE FTP SECURITY TESTING WARNING ⚠️",
        message: `This deep scan will perform INTENSIVE FTP penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for FTP (ftp-*)
• Performs comprehensive user enumeration
• Tests anonymous access with multiple techniques
• Evaluates directory traversal vulnerabilities
• Analyzes FTP bounce attack possibilities
• Generates extensive network traffic and logs

⚡ POTENTIAL IMPACT:
• May trigger intrusion detection systems
• Could cause temporary service slowdown
• Will generate security alerts and logs
• Multiple connection attempts may be logged

🛡️ LEGAL NOTICE:
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive FTP security test?`
    },
    ssh: {
        title: "⚠️ AGGRESSIVE SSH SECURITY TESTING WARNING ⚠️",
        message: `This deep scan will perform INTENSIVE SSH penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for SSH (ssh-*)
• Performs comprehensive algorithm security analysis
• Tests authentication methods and configurations
• Evaluates SSH protocol vulnerabilities
• Analyzes host key algorithms and security
• Checks for SSH-specific CVEs and weaknesses

⚡ POTENTIAL IMPACT:
• May trigger fail2ban or SSH protection systems
• Could exhaust SSH connection limits temporarily
• Will generate authentication logs and alerts
• SSH brute force protection may activate
• Extensive logging in system auth logs

🛡️ LEGAL NOTICE:
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive SSH security test?`
    },
    smtp: {
        title: "⚠️ AGGRESSIVE SMTP SECURITY TESTING WARNING ⚠️",
        message: `This deep scan will perform INTENSIVE SMTP penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for SMTP (smtp-*)
• Performs extensive user enumeration via VRFY/EXPN
• Conducts PASSWORD ATTACKS against discovered users
• Tests common passwords against mail accounts
• Analyzes mail relay and security configurations
• Evaluates SMTP command vulnerabilities

⚡ POTENTIAL IMPACT:
• WILL ATTEMPT TO CRACK USER PASSWORDS
• May trigger email security systems and alerts
• Could temporarily block your IP address
• Will generate extensive mail server logs
• Password attack attempts will be logged
• May affect mail server performance

🛡️ LEGAL NOTICE:
This scan includes PASSWORD ATTACKS which may be considered intrusive.
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive SMTP security test INCLUDING password attacks?`
    },
    smb: {
        title: "⚠️ AGGRESSIVE SMB SECURITY TESTING WARNING ⚠️",
        message: `This deep scan will perform INTENSIVE SMB penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for SMB (smb-enum*, smb-vuln*)
• Tests for EternalBlue and other critical vulnerabilities
• Performs comprehensive share enumeration and analysis
• Conducts PASSWORD BRUTE FORCE attacks (smb-brute)
• Tests SMB relay and signing bypass vulnerabilities
• Analyzes all SMB enumeration possibilities

⚡ POTENTIAL IMPACT:
• WILL ATTEMPT TO BRUTE FORCE SMB PASSWORDS
• May trigger Windows Defender and security systems
• Could temporarily lock out user accounts
• Will generate extensive Windows Event Logs
• Brute force attacks may cause account lockouts
• May affect SMB server performance

🛡️ LEGAL NOTICE:
This scan includes PASSWORD BRUTE FORCE ATTACKS and vulnerability testing.
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive SMB security test INCLUDING brute force attacks?`
    },

    snmp: {
        title: "⚠️ AGGRESSIVE SNMP SECURITY TESTING WARNING ⚠️",
        message: `This deep scan will perform INTENSIVE SNMP penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for SNMP (snmp-*)
• Performs SNMP community string brute force attacks
• Enumerates system information, users, and processes
• Extracts network interface configurations
• Attempts to discover Windows services and software
• Analyzes SNMP configuration vulnerabilities
• Tests for information disclosure via SNMP

⚡ POTENTIAL IMPACT:
• WILL ATTEMPT TO BRUTE FORCE SNMP COMMUNITY STRINGS
• May trigger network monitoring and SNMP alerts
• Could expose sensitive system and network information
• Will generate extensive SNMP query logs
• May affect network monitoring systems
• Could reveal infrastructure details

🛡️ LEGAL NOTICE:
This scan includes SNMP BRUTE FORCE ATTACKS and system enumeration.
Only proceed if you have explicit authorization to test this target.
Unauthorized SNMP scanning may violate network policies and regulations.

Do you want to continue with this aggressive SNMP security test INCLUDING brute force attacks?`
    }


};

const HTTP_DEEP_SCAN_WARNING = {
    title: "⚠️ AGGRESSIVE HTTP SECURITY TESTING WARNING ⚠️",
    message: `This deep scan will perform COMPREHENSIVE HTTP penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for HTTP (http-*)
• Performs extensive directory and file enumeration
• Tests for SQL injection, XSS, and other web vulnerabilities
• Conducts comprehensive web application security analysis
• Analyzes all HTTP methods and server configurations
• Tests authentication mechanisms and session security
• Generates extensive network traffic and logs

⚡ POTENTIAL IMPACT:
• May trigger Web Application Firewalls (WAF)
• Could cause temporary service slowdown
• Will generate security alerts and extensive logs
• Multiple vulnerability testing attempts will be logged
• May exhaust rate limits or trigger IP blocking

🛡️ LEGAL NOTICE:
This scan includes VULNERABILITY TESTING and may be considered intrusive.
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive HTTP security test?`
};

// Add HTTP warning to global warnings
if (typeof DEEP_SCAN_WARNINGS !== 'undefined') {
    DEEP_SCAN_WARNINGS.http = HTTP_DEEP_SCAN_WARNING;
}



function setupEventListeners() {
    // Mode buttons
    const manualModeBtn = document.getElementById('manualModeBtn');
    const templateModeBtn = document.getElementById('templateModeBtn');

    if (manualModeBtn) {
        manualModeBtn.addEventListener('click', () => switchScanMode('manual'));
    }
    if (templateModeBtn) {
        templateModeBtn.addEventListener('click', () => switchScanMode('template'));
    }

    // Import button
    const importBtn = document.getElementById('importFromPassiveBtn');
    if (importBtn) {
        importBtn.addEventListener('click', openImportModal);
    }

    // Modal close buttons
    const closeImportBtn = document.getElementById('closeImportModalBtn');
    if (closeImportBtn) {
        closeImportBtn.addEventListener('click', closeImportModal);
    }

    const cancelImportBtn = document.getElementById('cancelImportBtn');
    if (cancelImportBtn) {
        cancelImportBtn.addEventListener('click', closeImportModal);
    }

    const importSelectedBtn = document.getElementById('importSelectedBtn');
    if (importSelectedBtn) {
        importSelectedBtn.addEventListener('click', importSelectedTargets);
    }

    // Template scan button
    const startTemplateBtn = document.getElementById('startTemplateScansBtn');
    if (startTemplateBtn) {
        startTemplateBtn.addEventListener('click', startTemplateScans);
    }

    // Progress buttons
    const cancelScanBtn = document.getElementById('cancelScanBtn');
    if (cancelScanBtn) {
        cancelScanBtn.addEventListener('click', cancelScan);
    }

    // Results buttons
    const saveSessionBtn = document.getElementById('saveSessionBtn');
    if (saveSessionBtn) {
        saveSessionBtn.addEventListener('click', saveActiveScanSession);
    }

    const exportResultsBtn = document.getElementById('exportResultsBtn');
    if (exportResultsBtn) {
        exportResultsBtn.addEventListener('click', exportActiveScanResults);
    }

    // Scan type change
    const scanTypeSelect = document.getElementById('scanType');
    if (scanTypeSelect) {
        scanTypeSelect.addEventListener('change', updateScanDescription);
    }

    // Port input change for auto-detection
    const targetPortInput = document.getElementById('targetPort');
    if (targetPortInput) {
        targetPortInput.addEventListener('change', updateScanTypeBasedOnPort);
        targetPortInput.addEventListener('input', validatePortInput);
    }

    // IP input validation
    const targetIPInput = document.getElementById('targetIP');
    if (targetIPInput) {
        targetIPInput.addEventListener('input', validateIPInput);
        targetIPInput.addEventListener('blur', validateIPInput);
    }

    // Notification close
    const closeNotificationBtn = document.getElementById('closeNotificationBtn');
    if (closeNotificationBtn) {
        closeNotificationBtn.addEventListener('click', hideImportedTargetsNotification);
    }

    // Multiple targets modal
    const closeMultipleTargetsBtn = document.getElementById('closeMultipleTargetsBtn');
    if (closeMultipleTargetsBtn) {
        closeMultipleTargetsBtn.addEventListener('click', closeMultipleTargetsModal);
    }

    const setupBatchScanBtn = document.getElementById('setupBatchScanBtn');
    if (setupBatchScanBtn) {
        setupBatchScanBtn.addEventListener('click', setupBatchScan);
    }

    // Escape key to close modals
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeImportModal();
            closeMultipleTargetsModal();
        }
    });

    // Click outside modal to close
    document.addEventListener('click', function(event) {
        const importModal = document.getElementById('importModal');
        const multipleTargetsModal = document.getElementById('multipleTargetsModal');

        if (event.target === importModal) {
            closeImportModal();
        }
        if (event.target === multipleTargetsModal) {
            closeMultipleTargetsModal();
        }
    });
}

function checkForImportedTargets() {
    console.log('Checking for imported targets...');

    try {
        const urlParams = new URLSearchParams(window.location.search);
        const fromPassive = urlParams.get('from') === 'passive';
        const pendingScansData = sessionStorage.getItem('pendingActiveScans');

        if (fromPassive && pendingScansData) {
            try {
                const parsedTargets = JSON.parse(pendingScansData);
                if (parsedTargets && parsedTargets.length > 0) {
                    // Filter for supported ports including SMTP
                    const supportedTargets = parsedTargets.filter(target =>
                        SUPPORTED_PORTS.includes(parseInt(target.port))
                    );

                    if (supportedTargets.length > 0) {
                        pendingTargets = [...supportedTargets];
                        importedTargetsData = [...supportedTargets];
                        showImportedTargetsNotification();

                        if (supportedTargets.length === 1) {
                            autoPopulateTarget(supportedTargets[0]);
                        } else {
                            setTimeout(() => {
                                showMultipleTargetsSelection();
                            }, 1000);
                        }
                    } else {
                        Utils.showNotification('No supported ports found in imported targets', 'warning');
                    }
                }
            } catch (parseError) {
                console.error('Error parsing pending targets:', parseError);
                sessionStorage.removeItem('pendingActiveScans');
            }
        }
    } catch (error) {
        console.error('Error checking for imported targets:', error);
    }
}

function showImportedTargetsNotification() {
    const count = pendingTargets.length;
    const notification = document.getElementById('importedTargetsNotification');
    const countElement = document.getElementById('importedTargetsCount');

    if (notification && countElement) {
        countElement.textContent = `${count} target${count > 1 ? 's' : ''} ready for scanning`;
        notification.classList.remove('hidden');

        // Auto-hide after 8 seconds (increased time)
        setTimeout(() => {
            hideImportedTargetsNotification();
        }, 8000);
    }

    Utils.showNotification(`🚀 ${count} target${count > 1 ? 's' : ''} imported from passive scan`, 'success');
}

function hideImportedTargetsNotification() {
    const notification = document.getElementById('importedTargetsNotification');
    if (notification) {
        notification.classList.add('hidden');
    }
}

function autoPopulateTarget(target) {
    console.log('Auto-populating target:', target);

    const targetIPInput = document.getElementById('targetIP');
    const targetPortInput = document.getElementById('targetPort');

    if (targetIPInput && targetPortInput) {
        // Preserve the values
        targetIPInput.value = target.ip;
        targetPortInput.value = target.port;

        // Trigger validation
        targetIPInput.dispatchEvent(new Event('input'));
        targetPortInput.dispatchEvent(new Event('input'));

        // Update scan type based on port
        updateScanTypeBasedOnPort();

        // Switch to manual mode
        switchScanMode('manual');

        // Visual feedback
        setTimeout(() => {
            targetIPInput.style.boxShadow = '0 0 0 4px rgba(16, 185, 129, 0.3)';
            targetPortInput.style.boxShadow = '0 0 0 4px rgba(16, 185, 129, 0.3)';

            setTimeout(() => {
                targetIPInput.style.boxShadow = '';
                targetPortInput.style.boxShadow = '';
            }, 2000);
        }, 500);

        console.log('Target populated successfully:', target);
    }
}

function showMultipleTargetsSelection() {
    console.log('Showing multiple targets selection');

    const modal = document.getElementById('multipleTargetsModal');
    const subtitle = document.getElementById('multipleTargetsSubtitle');
    const targetsList = document.getElementById('multipleTargetsList');

    if (!modal || !targetsList) {
        console.error('Multiple targets modal elements not found');
        return;
    }

    // Update subtitle
    if (subtitle) {
        subtitle.textContent = `${pendingTargets.length} targets imported from passive scan`;
    }

    // Populate targets list
    targetsList.innerHTML = pendingTargets.map((target, index) => `
        <div class="imported-target-item" onclick="selectImportedTarget(${index})">
            <div class="target-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                </svg>
            </div>
            <div class="target-details">
                <div class="target-address">${target.ip}:${target.port}</div>
                <div class="target-service">${target.service} Service</div>
            </div>
            <div class="target-arrow">→</div>
        </div>
    `).join('');

    // Show modal
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeMultipleTargetsModal() {
    const modal = document.getElementById('multipleTargetsModal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function selectImportedTarget(index) {
    if (index >= 0 && index < pendingTargets.length) {
        const target = pendingTargets[index];
        autoPopulateTarget(target);
        closeMultipleTargetsModal();
        Utils.showNotification(`Target ${target.ip}:${target.port} loaded for scanning`, 'success');
    }
}

function setupBatchScan() {
    closeMultipleTargetsModal();

    // Switch to template mode
    switchScanMode('template');

    // Auto-select templates based on imported ports
    pendingTargets.forEach(target => {
        const port = parseInt(target.port);
        const templateCard = document.querySelector(`[data-port="${port}"]`);
        if (templateCard) {
            templateCard.classList.add('selected');
            selectedTemplates.add(port.toString());
        }
    });

    updateTemplateActions();
    Utils.showNotification(`Batch scan mode: ${selectedTemplates.size} services selected`, 'success');
}

function switchScanMode(mode) {
    console.log('Switching to mode:', mode);
    currentScanMode = mode;

    // Update mode buttons
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });

    // Show/hide mode content
    document.querySelectorAll('.scan-mode').forEach(modeDiv => {
        modeDiv.classList.toggle('active', modeDiv.id === mode + 'Mode');
    });
}

function setupScanForm() {
    const form = document.getElementById('activeScanForm');
    if (form) {
        // Remove any existing event listeners to prevent duplicates
        form.removeEventListener('submit', handleScanSubmit);
        form.addEventListener('submit', handleScanSubmit);
        console.log('Form event listener attached');
    } else {
        console.error("Form #activeScanForm not found");
    }
}

function handleScanSubmit(event) {
    event.preventDefault();
    console.log('Form submitted - preventing default behavior');

    if (activeScanInProgress) {
        Utils.showNotification('Scan already in progress', 'warning');
        return;
    }

    const targetIPInput = document.getElementById('targetIP');
    const targetPortInput = document.getElementById('targetPort');
    const scanTypeSelect = document.getElementById('scanType');
    const customWordlistInput = document.getElementById('customWordlist');

    if (!targetIPInput || !targetPortInput || !scanTypeSelect) {
        console.error('Form elements not found');
        Utils.showNotification('Form elements not found', 'error');
        return;
    }

    const targetIP = targetIPInput.value.trim();
    const targetPort = targetPortInput.value.trim();
    const scanType = scanTypeSelect.value;

    console.log('Form data:', { targetIP, targetPort, scanType });

    // Validation
    if (!Utils.validateIP(targetIP)) {
        Utils.showNotification('Please enter a valid IP address', 'error');
        targetIPInput.focus();
        return;
    }

    if (!Utils.validatePort(targetPort)) {
        Utils.showNotification('Please enter a valid port number', 'error');
        targetPortInput.focus();
        return;
    }

    const scanConfig = {
        targetIP,
        targetPort: parseInt(targetPort),
        scanType
    };

    // Add HTTPS scan intensity if HTTPS scan type
    if (scanType === 'https') {
        const intensitySelect = document.getElementById('httpsScanIntensity');
        if (intensitySelect) {
            scanConfig.httpsScanIntensity = intensitySelect.value;
            console.log('🔒 HTTPS scan intensity:', scanConfig.httpsScanIntensity);
        }
    }

    // Add custom wordlist if provided and scan type is HTTPS
    if (customWordlistInput && scanType === 'https') {
        const wordlistValue = customWordlistInput.value.trim();
        if (wordlistValue) {
            scanConfig.customWordlist = wordlistValue;
            console.log('🟢 CUSTOM WORDLIST ADDED TO HTTPS CONFIG');
        }
    }

    // Clear session storage
    if (importedTargetsData) {
        sessionStorage.removeItem('pendingActiveScans');
        console.log('Session storage cleared after scan start');
    }

    // Start scan
    startActiveScan(scanConfig);
}

// Initialize HTTPS functionality
document.addEventListener('DOMContentLoaded', function() {
    setupHTTPSScanIntensity();
});

function validateIPInput(event) {
    const input = event.target;
    const value = input.value.trim();

    if (value && !Utils.validateIP(value)) {
        input.setCustomValidity('Please enter a valid IP address');
        input.classList.add('invalid');
    } else {
        input.setCustomValidity('');
        input.classList.remove('invalid');
    }
}

function validatePortInput(event) {
    const input = event.target;
    const value = input.value.trim();

    if (value && !Utils.validatePort(value)) {
        input.setCustomValidity('Port must be between 1 and 65535');
        input.classList.add('invalid');
    } else {
        input.setCustomValidity('');
        input.classList.remove('invalid');
    }
}

function updateScanTypeBasedOnPort() {
    const portInput = document.getElementById('targetPort');
    const scanTypeSelect = document.getElementById('scanType');

    if (!portInput || !scanTypeSelect) return;

    const port = parseInt(portInput.value);
    const portMappings = {
        21: 'ftp',
        22: 'ssh',
        25: 'smtp',
        80: 'http',          // ✅ HTTP support for port 80
        139: 'smb',
        161: 'snmp',
        443: 'https',
        445: 'smb',
        465: 'smtp',
        587: 'smtp',
        990: 'ftp',
        2525: 'smtp',
        8000: 'http',
        8021: 'ftp',
        8080: 'auto',
        8443: 'https',
        9443: 'https'
    };

    if (portMappings[port]) {
        scanTypeSelect.value = portMappings[port];
        updateScanDescription();
    }
}

// Add HTTPS scan intensity selection handler
function setupHTTPSScanIntensity() {
    const intensitySelect = document.getElementById('httpsScanIntensity');
    if (intensitySelect) {
        intensitySelect.addEventListener('change', function() {
            updateHTTPSIntensityDescription();
        });
        updateHTTPSIntensityDescription(); // Initialize description
    }
}

Utils.getServiceType = function(port) {
    const serviceMap = {
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        161: 'SNMP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP',
        990: 'FTPS',
        2121: 'FTP',
        2525: 'SMTP',
        8021: 'FTP',
        8080: 'HTTP/HTTPS',
        8443: 'HTTPS',
        9443: 'HTTPS'
    };
    return serviceMap[parseInt(port)] || 'Unknown';
};

function updateHTTPSIntensityDescription() {
    const intensity = document.getElementById('httpsScanIntensity')?.value || 'normal';
    const descriptionDiv = document.getElementById('httpsIntensityDescription');

    if (!descriptionDiv) return;

    const descriptions = {
        normal: '🟢 Safe scan - Basic SSL/TLS security check, certificate validation, and security headers analysis. Won\'t trigger security alerts.',
        aggressive: '🔴 Deep scan - Comprehensive vulnerability testing, directory enumeration, and extensive security analysis. May trigger security systems.'
    };

    descriptionDiv.textContent = descriptions[intensity];
    descriptionDiv.className = `intensity-description ${intensity}`;
}

const HTTPS_DEEP_SCAN_WARNING = {
    title: "⚠️ AGGRESSIVE HTTPS SECURITY TESTING WARNING ⚠️",
    message: `This deep scan will perform COMPREHENSIVE HTTPS penetration testing:

🔍 WHAT IT DOES:
• Executes ALL nmap NSE scripts for HTTPS (ssl-*, http-*)
• Performs extensive directory and file enumeration
• Tests for SQL injection, XSS, and other web vulnerabilities
• Conducts comprehensive SSL/TLS security analysis
• Analyzes all cipher suites and protocol weaknesses
• Tests authentication mechanisms and session security
• Generates extensive network traffic and logs

⚡ POTENTIAL IMPACT:
• May trigger Web Application Firewalls (WAF)
• Could cause temporary service slowdown
• Will generate security alerts and extensive logs
• Multiple vulnerability testing attempts will be logged
• May exhaust rate limits or trigger IP blocking

🛡️ LEGAL NOTICE:
This scan includes VULNERABILITY TESTING and may be considered intrusive.
Only proceed if you have explicit authorization to test this target.
Unauthorized security testing may violate laws and regulations.

Do you want to continue with this aggressive HTTPS security test?`
};

function showDeepHTTPSScanButton(scanData) {
    console.log('🔍 HTTPS Debug - showDeepHTTPSScanButton called with:', scanData);

    // Check if we have nmap data
    const hasNmap = scanData.nmap_data && !scanData.nmap_data.error;

    if (!hasNmap) {
        console.log('🔍 HTTPS Debug - Deep HTTPS scan not available - nmap not available or failed');
        return;
    }

    // Check if button already exists
    const existingBtn = document.getElementById('deepHTTPSScanBtn');
    if (existingBtn) {
        existingBtn.remove();
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-https-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep HTTPS Scan (All Scripts + Web Vuln Testing)</span>
    `;
    deepScanBtn.id = 'deepHTTPSScanBtn';
    deepScanBtn.onclick = () => startDeepHTTPSScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep HTTPS Scan button added successfully');
    }
}

async function startDeepHTTPSScan(previousScanData) {
    console.log('🎯 Starting deep HTTPS scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(HTTPS_DEEP_SCAN_WARNING.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep HTTPS scan');
        Utils.showNotification('Deep HTTPS scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep HTTPS scan - proceeding...');

    const deepBtn = document.getElementById('deepHTTPSScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All HTTPS Scripts + Vulnerability Testing...</span>
        `;
    }

    try {
        showDeepHTTPSScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'https',
            normal_scan_results: previousScanData
        };

        console.log('🚀 Starting deep HTTPS scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep HTTPS scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep HTTPS scan results:', deepResults);

        showDeepHTTPSResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep HTTPS scan error:', error);
        Utils.showNotification(`Deep HTTPS scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep HTTPS Scan (All Scripts + Web Vuln Testing)</span>
            `;
        }
    }
}

function showDeepHTTPSScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'HTTPS (Deep Scan - All Scripts + Web Vulnerability Testing)';
    }

    updateScanProgress(25, 'Loading comprehensive HTTPS NSE script suite...');
    setTimeout(() => updateScanProgress(50, 'Running ssl-*, http-* scripts and web vulnerability tests...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep HTTPS and web security findings...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep HTTPS scan completed'), 3000);
}

// Show Deep HTTPS Results
function showDeepHTTPSResults(deepResults, originalResults) {
    console.log('🔍 Showing deep HTTPS scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep HTTPS Scan Results (SSL/TLS + Web Vulnerability Testing)
            <span class="deep-scan-badge">Complete</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show SSL/TLS vulnerability results FIRST (most important)
    if (deepResults.advanced_findings && deepResults.advanced_findings.ssl_analysis) {
        const sslAnalysis = deepResults.advanced_findings.ssl_analysis;
        const sslCard = document.createElement('div');
        sslCard.className = 'result-card ssl-analysis-card';
        sslCard.innerHTML = `
            <h4>🔒 SSL/TLS Security Analysis</h4>
            <div class="ssl-analysis-content">
                ${formatSSLAnalysis(sslAnalysis)}
            </div>
        `;
        resultsContent.appendChild(sslCard);
    }

    // Show web vulnerability results
    if (deepResults.advanced_findings && deepResults.advanced_findings.web_analysis) {
        const webAnalysis = deepResults.advanced_findings.web_analysis;
        const webCard = document.createElement('div');
        webCard.className = 'result-card web-analysis-card';
        webCard.innerHTML = `
            <h4>🌐 Web Security Analysis</h4>
            <div class="web-analysis-content">
                ${formatWebAnalysis(webAnalysis)}
            </div>
        `;
        resultsContent.appendChild(webCard);
    }

    // Show raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep HTTPS Scan Output</h4>
            <div class="nmap-command-info">
                <strong>Command:</strong> ${deepResults.nmap_data.command_used || 'nmap -sV -A -p443 --script "ssl-*,http-*"'}
            </div>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;
        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepHTTPSScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    // Notification
    const vulnCount = deepResults.vulnerabilities?.length || 0;
    if (vulnCount > 0) {
        Utils.showNotification(`🔒 HTTPS Deep Scan: ${vulnCount} security issues found`, 'warning');
    } else {
        Utils.showNotification('Deep HTTPS scan completed successfully', 'success');
    }

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

// Format SSL Analysis Results
function formatSSLAnalysis(sslAnalysis) {
    let html = '<div class="ssl-analysis-container">';

    if (sslAnalysis.certificate_info) {
        html += `
            <div class="ssl-section">
                <h5>📜 Certificate Information</h5>
                <div class="certificate-info">
                    ${safeDisplayValue(sslAnalysis.certificate_info)}
                </div>
            </div>
        `;
    }

    if (sslAnalysis.cipher_analysis) {
        html += `
            <div class="ssl-section">
                <h5>🔐 Cipher Suite Analysis</h5>
                <div class="cipher-analysis">
                    ${safeDisplayValue(sslAnalysis.cipher_analysis)}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// Format Web Analysis Results
function formatWebAnalysis(webAnalysis) {
    let html = '<div class="web-analysis-container">';

    if (webAnalysis.security_headers) {
        html += `
            <div class="web-section">
                <h5>🛡️ Security Headers Analysis</h5>
                <div class="security-headers">
                    ${formatSecurityHeaders(webAnalysis.security_headers)}
                </div>
            </div>
        `;
    }

    if (webAnalysis.directories_found) {
        html += `
            <div class="web-section">
                <h5>📁 Directories Found</h5>
                <div class="directories-found">
                    ${safeDisplayValue(webAnalysis.directories_found)}
                </div>
            </div>
        `;
    }

    if (webAnalysis.backup_files) {
        html += `
            <div class="web-section">
                <h5>📄 Backup Files Found</h5>
                <div class="backup-files">
                    ${safeDisplayValue(webAnalysis.backup_files)}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// Format Security Headers
function formatSecurityHeaders(headersAnalysis) {
    if (typeof headersAnalysis === 'string') {
        return `<pre>${safeDisplayValue(headersAnalysis)}</pre>`;
    }

    let html = '<div class="security-headers-analysis">';

    if (headersAnalysis.headers_present && headersAnalysis.headers_present.length > 0) {
        html += `
            <div class="headers-present">
                <strong>✅ Security Headers Present:</strong>
                <ul>
                    ${headersAnalysis.headers_present.map(header => `<li>${safeDisplayValue(header)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (headersAnalysis.missing_headers && headersAnalysis.missing_headers.length > 0) {
        html += `
            <div class="headers-missing">
                <strong>❌ Missing Security Headers:</strong>
                <ul>
                    ${headersAnalysis.missing_headers.map(header => `<li>${safeDisplayValue(header)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// HTTPS Vulnerability Item Renderer
function renderHTTPSVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'https_scanner';

    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap_ssl') || vuln.detection_method?.includes('ssl-')) {
        badgeText = 'SSL ANALYSIS';
        badgeClass = 'ssl-badge';
    } else if (source.includes('nmap_http') || vuln.detection_method?.includes('http-')) {
        badgeText = 'WEB ANALYSIS';
        badgeClass = 'web-badge';
    } else if (source.includes('certificate_analysis')) {
        badgeText = 'CERTIFICATE';
        badgeClass = 'cert-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} https-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'HTTPS-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'HTTPS Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function updateScanDescription() {
    const scanType = document.getElementById('scanType')?.value;
    const descriptionDiv = document.getElementById('scanDescription');
    const httpsOptions = document.getElementById('httpsOptions');
    const httpOptions = document.getElementById('httpOptions');

    if (!descriptionDiv) return;

    const descriptions = {
        auto: 'Automatically detect service type and run appropriate tests.',
        http: 'Comprehensive HTTP web application security assessment including server configuration analysis, security headers testing, web vulnerability scanning, HTTP methods analysis, and directory enumeration.',
        ftp: 'Advanced FTP enumeration including anonymous access testing, directory traversal detection, bounce attack assessment, and comprehensive security evaluation.',
        ssh: 'SSH service analysis including banner grabbing, authentication methods, algorithm security assessment, and user enumeration.',
        smtp: 'Comprehensive SMTP mail server assessment including open relay testing, user enumeration, command analysis, and DNS security configuration (SPF, DKIM, DMARC) evaluation.',
        snmp: 'SNMP enumeration including system information gathering, community string testing, network interface discovery, and comprehensive device information extraction.',
        https: 'Comprehensive HTTPS/SSL security assessment including certificate analysis, cipher suite evaluation, security headers testing, web vulnerability scanning, and SSL/TLS protocol security analysis.',
        smb: 'SMB file sharing analysis with share enumeration, vulnerability assessment, and security configuration testing.'
    };

    descriptionDiv.textContent = descriptions[scanType] || descriptions.auto;

    // Show/hide HTTP options
    if (httpOptions) {
        httpOptions.style.display = (scanType === 'http') ? 'block' : 'none';
    }

    // Show/hide HTTPS options
    if (httpsOptions) {
        httpsOptions.style.display = (scanType === 'https') ? 'block' : 'none';
    }
}

// Update the Utils.getServiceType function to include HTTP
Utils.getServiceType = function(port) {
    const serviceMap = {
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        80: 'HTTP',
        139: 'SMB',
        161: 'SNMP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP',
        990: 'FTPS',
        2121: 'FTP',
        2525: 'SMTP',
        8000: 'HTTP',
        8021: 'FTP',
        8080: 'HTTP/HTTPS',
        8443: 'HTTPS',
        9443: 'HTTPS'
    };
    return serviceMap[parseInt(port)] || 'Unknown';
};

function showDeepHTTPScanButton(scanData) {
    console.log('🔍 HTTP Debug - showDeepHTTPScanButton called with:', scanData);

    // Check if we have nmap data
    const hasNmap = scanData.nmap_data && !scanData.nmap_data.error;

    if (!hasNmap) {
        console.log('🔍 HTTP Debug - Deep HTTP scan not available - nmap not available or failed');
        return;
    }

    // Check if button already exists
    const existingBtn = document.getElementById('deepHTTPScanBtn');
    if (existingBtn) {
        existingBtn.remove();
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-http-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep HTTP Scan (All Scripts + Web Vuln Testing)</span>
    `;
    deepScanBtn.id = 'deepHTTPScanBtn';
    deepScanBtn.onclick = () => startDeepHTTPScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep HTTP Scan button added successfully');
    }
}

// 2. Start Deep HTTP Scan
async function startDeepHTTPScan(previousScanData) {
    console.log('🎯 Starting deep HTTP scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(HTTP_DEEP_SCAN_WARNING.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep HTTP scan');
        Utils.showNotification('Deep HTTP scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep HTTP scan - proceeding...');

    const deepBtn = document.getElementById('deepHTTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All HTTP Scripts + Web Vulnerability Testing...</span>
        `;
    }

    try {
        showDeepHTTPScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'http',
            normal_scan_results: previousScanData
        };

        console.log('🚀 Starting deep HTTP scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep HTTP scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep HTTP scan results:', deepResults);

        showDeepHTTPResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep HTTP scan error:', error);
        Utils.showNotification(`Deep HTTP scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep HTTP Scan (All Scripts + Web Vuln Testing)</span>
            `;
        }
    }
}

// 3. Show Deep HTTP Scan Progress
function showDeepHTTPScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'HTTP (Deep Scan - All Scripts + Web Vulnerability Testing)';
    }

    updateScanProgress(25, 'Loading comprehensive HTTP NSE script suite...');
    setTimeout(() => updateScanProgress(50, 'Running http-* scripts and web vulnerability tests...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep HTTP and web security findings...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep HTTP scan completed'), 3000);
}

// 4. Show Deep HTTP Results
function showDeepHTTPResults(deepResults, originalResults) {
    console.log('🔍 Showing deep HTTP scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep HTTP Scan Results (Web Application + Server Security Testing)
            <span class="deep-scan-badge">Complete</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show web vulnerability results FIRST (most important)
    if (deepResults.advanced_findings && deepResults.advanced_findings.web_analysis) {
        const webAnalysis = deepResults.advanced_findings.web_analysis;
        const webCard = document.createElement('div');
        webCard.className = 'result-card web-analysis-card';
        webCard.innerHTML = `
            <h4>🌐 Web Application Security Analysis</h4>
            <div class="web-analysis-content">
                ${formatHTTPWebAnalysis(webAnalysis)}
            </div>
        `;
        resultsContent.appendChild(webCard);
    }

    // Show server security results
    if (deepResults.advanced_findings && deepResults.advanced_findings.server_analysis) {
        const serverAnalysis = deepResults.advanced_findings.server_analysis;
        const serverCard = document.createElement('div');
        serverCard.className = 'result-card server-analysis-card';
        serverCard.innerHTML = `
            <h4>🖥️ HTTP Server Security Analysis</h4>
            <div class="server-analysis-content">
                ${formatHTTPServerAnalysis(serverAnalysis)}
            </div>
        `;
        resultsContent.appendChild(serverCard);
    }

    // Show raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep HTTP Scan Output</h4>
            <div class="nmap-command-info">
                <strong>Command:</strong> ${deepResults.nmap_data.command_used || 'nmap -sV -A --script "http-*"'}
            </div>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;
        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepHTTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    // Notification
    const vulnCount = deepResults.vulnerabilities?.length || 0;
    if (vulnCount > 0) {
        Utils.showNotification(`🌐 HTTP Deep Scan: ${vulnCount} security issues found`, 'warning');
    } else {
        Utils.showNotification('Deep HTTP scan completed successfully', 'success');
    }

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

// 5. Format HTTP Web Analysis Results
function formatHTTPWebAnalysis(webAnalysis) {
    let html = '<div class="http-web-analysis-container">';

    if (webAnalysis.security_headers) {
        html += `
            <div class="web-section">
                <h5>🛡️ Security Headers Analysis</h5>
                <div class="security-headers">
                    ${formatHTTPSecurityHeaders(webAnalysis.security_headers)}
                </div>
            </div>
        `;
    }

    if (webAnalysis.directories_found) {
        html += `
            <div class="web-section">
                <h5>📁 Directory Enumeration Results</h5>
                <div class="directories-found">
                    ${formatHTTPDirectories(webAnalysis.directories_found)}
                </div>
            </div>
        `;
    }

    if (webAnalysis.backup_files) {
        html += `
            <div class="web-section">
                <h5>📄 Backup Files Found</h5>
                <div class="backup-files">
                    ${formatHTTPBackupFiles(webAnalysis.backup_files)}
                </div>
            </div>
        `;
    }

    if (webAnalysis.vulnerability_tests) {
        html += `
            <div class="web-section">
                <h5>🔍 Vulnerability Test Results</h5>
                <div class="vulnerability-tests">
                    ${formatHTTPVulnerabilityTests(webAnalysis.vulnerability_tests)}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// 6. Format HTTP Server Analysis Results
function formatHTTPServerAnalysis(serverAnalysis) {
    let html = '<div class="http-server-analysis-container">';

    if (serverAnalysis.server_info) {
        html += `
            <div class="server-section">
                <h5>🖥️ Server Information</h5>
                <div class="server-info">
                    ${formatHTTPServerInfo(serverAnalysis.server_info)}
                </div>
            </div>
        `;
    }

    if (serverAnalysis.methods_analysis) {
        html += `
            <div class="server-section">
                <h5>⚙️ HTTP Methods Analysis</h5>
                <div class="methods-analysis">
                    ${formatHTTPMethodsAnalysis(serverAnalysis.methods_analysis)}
                </div>
            </div>
        `;
    }

    if (serverAnalysis.authentication_tests) {
        html += `
            <div class="server-section">
                <h5>🔐 Authentication Testing</h5>
                <div class="authentication-tests">
                    ${formatHTTPAuthTests(serverAnalysis.authentication_tests)}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// 7. Helper Functions for HTTP Formatting
function formatHTTPSecurityHeaders(headersAnalysis) {
    if (typeof headersAnalysis === 'string') {
        return `<pre>${safeDisplayValue(headersAnalysis)}</pre>`;
    }

    let html = '<div class="security-headers-analysis">';

    if (headersAnalysis.headers_present && headersAnalysis.headers_present.length > 0) {
        html += `
            <div class="headers-present">
                <strong>✅ Security Headers Present:</strong>
                <ul>
                    ${headersAnalysis.headers_present.map(header => `<li>${safeDisplayValue(header)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (headersAnalysis.missing_headers && headersAnalysis.missing_headers.length > 0) {
        html += `
            <div class="headers-missing">
                <strong>❌ Missing Security Headers:</strong>
                <ul>
                    ${headersAnalysis.missing_headers.map(header => `<li>${safeDisplayValue(header)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatHTTPDirectories(directoriesData) {
    if (typeof directoriesData === 'string') {
        return `<pre>${safeDisplayValue(directoriesData)}</pre>`;
    }

    if (Array.isArray(directoriesData)) {
        return `
            <div class="directories-list">
                ${directoriesData.map(dir => `
                    <div class="directory-item">
                        ${typeof dir === 'object' ? 
                            `<strong>${safeDisplayValue(dir.path || dir.url)}</strong> - Status: ${dir.status || 'Found'}` :
                            safeDisplayValue(dir)
                        }
                    </div>
                `).join('')}
            </div>
        `;
    }

    return `<pre>${safeDisplayValue(directoriesData)}</pre>`;
}

function formatHTTPBackupFiles(backupFiles) {
    if (typeof backupFiles === 'string') {
        return `<pre>${safeDisplayValue(backupFiles)}</pre>`;
    }

    if (Array.isArray(backupFiles)) {
        return `
            <div class="backup-files-list">
                ${backupFiles.map(file => `
                    <div class="backup-file-item critical">
                        ${typeof file === 'object' ? 
                            `<strong>${safeDisplayValue(file.path || file.url)}</strong> - ${file.status || 'Found'}` :
                            safeDisplayValue(file)
                        }
                    </div>
                `).join('')}
            </div>
        `;
    }

    return `<pre>${safeDisplayValue(backupFiles)}</pre>`;
}

function formatHTTPVulnerabilityTests(vulnTests) {
    let html = '<div class="vulnerability-tests-container">';

    if (vulnTests.sql_injection) {
        html += `
            <div class="vuln-test-item ${vulnTests.sql_injection.vulnerable ? 'vulnerable' : 'secure'}">
                <strong>SQL Injection Test:</strong> ${vulnTests.sql_injection.vulnerable ? '⚠️ VULNERABLE' : '✅ SECURE'}
                ${vulnTests.sql_injection.details ? `<div class="test-details">${safeDisplayValue(vulnTests.sql_injection.details)}</div>` : ''}
            </div>
        `;
    }

    if (vulnTests.xss_test) {
        html += `
            <div class="vuln-test-item ${vulnTests.xss_test.vulnerable ? 'vulnerable' : 'secure'}">
                <strong>XSS Test:</strong> ${vulnTests.xss_test.vulnerable ? '⚠️ VULNERABLE' : '✅ SECURE'}
                ${vulnTests.xss_test.details ? `<div class="test-details">${safeDisplayValue(vulnTests.xss_test.details)}</div>` : ''}
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatHTTPServerInfo(serverInfo) {
    let html = '<div class="server-info-grid">';

    Object.entries(serverInfo).forEach(([key, value]) => {
        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        html += `
            <div class="server-info-item">
                <strong>${displayKey}:</strong> ${safeDisplayValue(value)}
            </div>
        `;
    });

    html += '</div>';
    return html;
}

function formatHTTPMethodsAnalysis(methodsData) {
    let html = '<div class="methods-analysis-container">';

    if (methodsData.allowed_methods) {
        html += `
            <div class="methods-section">
                <strong>Allowed Methods:</strong>
                <div class="methods-list">
                    ${methodsData.allowed_methods.map(method => `
                        <span class="method-badge ${methodsData.dangerous_methods?.includes(method) ? 'dangerous' : 'safe'}">${method}</span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    if (methodsData.dangerous_methods && methodsData.dangerous_methods.length > 0) {
        html += `
            <div class="methods-section">
                <strong>⚠️ Dangerous Methods:</strong>
                <div class="methods-list">
                    ${methodsData.dangerous_methods.map(method => `
                        <span class="method-badge dangerous">${method}</span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatHTTPAuthTests(authTests) {
    let html = '<div class="auth-tests-container">';

    Object.entries(authTests).forEach(([testName, result]) => {
        html += `
            <div class="auth-test-item">
                <strong>${testName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</strong>
                ${safeDisplayValue(result)}
            </div>
        `;
    });

    html += '</div>';
    return html;
}

// 8. HTTP Vulnerability Item Renderer
function renderHTTPVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'http_scanner';

    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap_http') || vuln.detection_method?.includes('http-')) {
        badgeText = 'NMAP HTTP';
        badgeClass = 'nmap-badge';
    } else if (source.includes('web_analysis')) {
        badgeText = 'WEB ANALYSIS';
        badgeClass = 'web-badge';
    } else if (source.includes('server_analysis')) {
        badgeText = 'SERVER';
        badgeClass = 'server-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} http-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'HTTP-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'HTTP Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

// 9. Format HTTP Service Info (clean, no external dependencies)
function formatHTTPServiceInfo(serviceInfo, serviceType) {
    let html = '';

    // Basic HTTP service information
    if (serviceInfo.service_name || serviceType) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Type:</span>
                <span class="service-value">${serviceInfo.service_name || serviceType.toUpperCase()}</span>
            </div>
        `;
    }

    if (serviceInfo.server_type) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Web Server:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.server_type)}</span>
            </div>
        `;
    }

    if (serviceInfo.version || serviceInfo.service_version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Version:</span>
                <span class="service-value">${serviceInfo.version || serviceInfo.service_version}</span>
            </div>
        `;
    }

    if (serviceInfo.banner) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">HTTP Banner:</span>
                <span class="service-value banner-text">${safeDisplayValue(serviceInfo.banner)}</span>
            </div>
        `;
    }

    // HTTP-specific fields
    if (serviceInfo.status_code) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">HTTP Status:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.status_code)}</span>
            </div>
        `;
    }

    if (serviceInfo.content_type) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Content Type:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.content_type)}</span>
            </div>
        `;
    }

    // Response time
    if (serviceInfo.response_time_ms || serviceInfo.connection_time) {
        const responseTime = serviceInfo.response_time_ms || serviceInfo.connection_time;
        html += `
            <div class="service-detail-row">
                <span class="service-label">Response Time:</span>
                <span class="service-value">${responseTime}ms</span>
            </div>
        `;
    }

    if (serviceInfo.accessible !== undefined) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Accessible:</span>
                <span class="service-value">${serviceInfo.accessible ? '✅ Yes' : '❌ No'}</span>
            </div>
        `;
    }

    // Fallback content if nothing was added
    if (!html.trim()) {
        html = `
            <div class="service-detail-row">
                <span class="service-label">Service Detected:</span>
                <span class="service-value">${serviceType.toUpperCase()} service is running</span>
            </div>
            <div class="service-detail-row">
                <span class="service-label">Port Status:</span>
                <span class="service-value">✅ Open and Accessible</span>
            </div>
        `;
    }

    return html;
}

// 10. Format HTTP Advanced Findings
function formatHTTPAdvancedFindings(findings) {
    let html = '<div class="http-advanced-findings-content">';

    // Web Application Analysis
    if (findings.web_analysis) {
        html += formatHTTPWebAnalysis(findings.web_analysis);
    }

    // Server Analysis
    if (findings.server_analysis) {
        html += formatHTTPServerAnalysis(findings.server_analysis);
    }

    html += '</div>';
    return html;
}

function setupTemplateCards() {
    const templateCards = document.querySelectorAll('.template-card');

    templateCards.forEach(card => {
        card.addEventListener('click', function() {
            selectTemplate(this);
        });
    });
}

function selectTemplate(card) {
    const port = card.dataset.port;

    if (selectedTemplates.has(port)) {
        selectedTemplates.delete(port);
        card.classList.remove('selected');
    } else {
        selectedTemplates.add(port);
        card.classList.add('selected');
    }

    updateTemplateActions();
}

function updateTemplateActions() {
    const selectedCount = document.getElementById('selectedCount');
    const startButton = document.getElementById('startTemplateScansBtn');

    const count = selectedTemplates.size;

    if (selectedCount) {
        selectedCount.textContent = `${count} selected`;
    }

    if (startButton) {
        startButton.disabled = count === 0;
        if (count > 0) {
            startButton.innerHTML = `
                <span>Start ${count} Selected Scan${count > 1 ? 's' : ''}</span>
            `;
        } else {
            startButton.innerHTML = `
                <span>Start Selected Scans</span>
                <span class="selected-count">0 selected</span>
            `;
        }
    }
}

function startTemplateScans() {
    if (selectedTemplates.size === 0) {
        Utils.showNotification('Please select at least one template', 'warning');
        return;
    }

    // Get target IP from manual mode or use imported data
    const targetIPInput = document.getElementById('targetIP');
    let targetIP = targetIPInput?.value?.trim();

    // If no IP in manual mode, try to get from imported targets
    if (!targetIP && importedTargetsData && importedTargetsData.length > 0) {
        targetIP = importedTargetsData[0].ip;
    }

    if (!targetIP) {
        targetIP = '127.0.0.1'; // Default fallback
    }

    if (!Utils.validateIP(targetIP)) {
        Utils.showNotification('Please enter a valid IP address in the manual entry section', 'error');
        return;
    }

    // Clear session storage as we're starting the scan
    if (importedTargetsData) {
        sessionStorage.removeItem('pendingActiveScans');
        console.log('Session storage cleared after template scan start');
    }

    // Start with the first selected template
    const firstPort = Array.from(selectedTemplates)[0];
    const templateCard = document.querySelector(`[data-port="${firstPort}"]`);
    const scanType = templateCard?.dataset.type || 'auto';

    startActiveScan({
        targetIP,
        targetPort: parseInt(firstPort),
        scanType
    });
}

async function startActiveScan(config) {
    console.log('Starting active scan with config:', config);

    activeScanInProgress = true;

    try {
        // Show progress section
        showScanProgress(config);

        // Start the actual scan
        await performActiveScan(config);

    } catch (error) {
        console.error('Active scan failed:', error);
        Utils.handleError(error, 'Active scan');
        hideScanProgress();
    } finally {
        activeScanInProgress = false;
    }
}

function showScanProgress(config){
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    // Update scan info
    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${config.targetIP}:${config.targetPort}`;
    }

    if (serviceElement) {
        const serviceNames = {
            ssh: 'SSH',
            smtp: 'SMTP',
            snmp: 'SNMP',
            https: 'HTTPS/SSL',
            smb: 'SMB',
            ftp: 'FTP'
        };
        serviceElement.textContent = serviceNames[config.scanType] || 'Auto-detect';
    }

    // Reset progress
    updateScanProgress(0, 'Initializing scan...');
    resetStepIndicators();

    // Show cancel button when scan starts
    showCancelButton();

    // Start timer
    startScanTimer();

    // Scroll to progress section
    progressSection.scrollIntoView({ behavior: 'smooth' });
}

function hideScanProgress() {
    const progressSection = document.getElementById('scanProgressSection');

    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    hideCancelButton();
}

function updateScanProgress(percentage, stepMessage) {
    const progressFill = document.getElementById('overallProgress');
    const progressPercentage = document.getElementById('progressPercentage');
    const currentStep = document.getElementById('currentStep');

    if (progressFill) {
        progressFill.style.width = `${percentage}%`;
    }

    if (progressPercentage) {
        progressPercentage.textContent = `${percentage}%`;
    }

    if (currentStep) {
        currentStep.textContent = stepMessage;
    }
}

function updateStepStatus(stepName, status) {
    const step = document.querySelector(`[data-step="${stepName}"]`);
    if (!step) return;

    // Remove all status classes
    step.classList.remove('active', 'completed');

    // Add current status
    if (status === 'active') {
        step.classList.add('active');
        const statusText = step.querySelector('.status-text');
        if (statusText) statusText.textContent = 'In Progress';
    } else if (status === 'completed') {
        step.classList.add('completed');
        const statusText = step.querySelector('.status-text');
        if (statusText) statusText.textContent = 'Completed';

        // Update icon
        const icon = step.querySelector('.step-icon');
        if (icon) icon.textContent = '✓';
    }
}

function resetStepIndicators() {
    document.querySelectorAll('.step').forEach((step, index) => {
        step.classList.remove('active', 'completed');
        const statusText = step.querySelector('.status-text');
        if (statusText) statusText.textContent = 'Pending';

        const icon = step.querySelector('.step-icon');
        if (icon) icon.textContent = index + 1;
    });
}

function startScanTimer() {
    const timerElement = document.getElementById('scanTime');
    if (!timerElement) return;

    const startTime = Date.now();

    const timer = setInterval(() => {
        if (!activeScanInProgress) {
            clearInterval(timer);
            return;
        }

        const elapsed = Date.now() - startTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);

        timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }, 1000);
}

async function performActiveScan(config) {
    try {
        console.log('🚀 Performing active scan with backend...');
        console.log('📊 Full scan config received:', config);

        // Start the scan with backend API call
        updateStepStatus('banner', 'active');
        updateScanProgress(10, 'Connecting to target...');

        // Prepare request payload (NO SHODAN)
        const payload = {
            targetIP: config.targetIP,
            targetPort: config.targetPort,
            scanType: config.scanType,
            enhancedMode: config.enhancedMode || false,
            useEnhancedNmap: config.useEnhancedNmap || false
        };

        // Add custom wordlist if provided
        if (config.customWordlist) {
            payload.customWordlist = config.customWordlist;
            const lineCount = config.customWordlist.split('\n').filter(line => line.trim()).length;
            console.log('✅ FRONTEND: Custom wordlist detected!');
            updateScanProgress(15, `Using custom wordlist (${lineCount} paths)...`);
        }

        console.log('🟢 FRONTEND: About to send payload:', payload);

        const response = await fetch('/api/active-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            let errorMessage = `Scan failed: ${response.statusText}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorMessage;

                // Handle specific error cases
                if (errorData.supported_ports) {
                    errorMessage += `\nSupported ports: ${errorData.supported_ports.join(', ')}`;
                }
            } catch (e) {
                // If can't parse JSON, use status text
            }
            throw new Error(errorMessage);
        }

        const scanData = await response.json();
        console.log('📥 Received scan data from backend:', scanData);

        // Check if scan failed
        if (scanData.status === 'error') {
            throw new Error(scanData.error || 'Active scan failed');
        }

        // Handle the response from your ActiveScanner
        if (scanData.steps_completed) {
            // Simulate progress updates based on completed steps
            await updateProgressBasedOnSteps(scanData.steps_completed);
        } else {
            // If no steps_completed, simulate standard progress
            await simulateStandardProgress();
        }

        // Show final results
        setTimeout(() => {
            showScanResults(scanData);



        }, 500);

    } catch (error) {
        console.error('❌ Scan execution error:', error);

        // Check if it's a network connectivity issue
        if (error.message.includes('Failed to fetch') ||
            error.message.includes('NetworkError') ||
            error.message.includes('ERR_NETWORK')) {
            Utils.showNotification('Network error: Cannot connect to server', 'error');
        } else {
            throw error;
        }
    }
}

async function simulateStandardProgress() {
    const steps = [
        { name: 'banner', progress: 25, message: 'Banner grabbing completed' },
        { name: 'fingerprint', progress: 50, message: 'Service fingerprinting completed' },
        { name: 'enumeration', progress: 75, message: 'Service enumeration completed' },
        { name: 'vulnerability', progress: 100, message: 'Vulnerability assessment completed' }
    ];

    for (const step of steps) {
        updateStepStatus(step.name, 'active');
        updateScanProgress(step.progress, step.message);
        await new Promise(resolve => setTimeout(resolve, 800));
        updateStepStatus(step.name, 'completed');
    }
}

async function updateProgressBasedOnSteps(completedSteps) {
    const stepInfo = {
        'banner': { progress: 25, message: 'Banner grabbing completed' },
        'fingerprint': { progress: 50, message: 'Service fingerprinting completed' },
        'enumeration': { progress: 75, message: 'Service enumeration completed' },
        'vulnerability': { progress: 100, message: 'Vulnerability assessment completed' }
    };

    const allSteps = ['banner', 'fingerprint', 'enumeration', 'vulnerability'];

    for (let i = 0; i < allSteps.length; i++) {
        const stepName = allSteps[i];

        if (completedSteps.includes(stepName)) {
            // Step completed
            updateStepStatus(stepName, 'active');
            updateScanProgress(stepInfo[stepName].progress, stepInfo[stepName].message);

            // Add delay for visual effect
            await new Promise(resolve => setTimeout(resolve, 800));

            updateStepStatus(stepName, 'completed');
        }
    }
}




function formatSSHAuditProfessional(rawOutput) {
    try {
        // If it's JSON, parse and format it nicely
        if (rawOutput.trim().startsWith('{')) {
            const jsonData = JSON.parse(rawOutput);
            return formatSSHAuditFromJSON(jsonData);
        }
        // Otherwise return as-is (text format)
        return `<pre class="ssh-text-output">${safeDisplayValue(rawOutput)}</pre>`;
    } catch (e) {
        // If JSON parsing fails, return formatted text
        return `<pre class="ssh-text-output">${safeDisplayValue(rawOutput)}</pre>`;
    }
}

// Helper function to format JSON into professional SSH report
function formatSSHAuditFromJSON(jsonData) {
    let html = '<div class="ssh-professional-analysis">';

    // Banner Information
    if (jsonData.banner) {
        html += `
            <div class="ssh-section">
                <h6>🖥️ SSH Server Information</h6>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Banner:</span>
                        <span class="info-value">${safeDisplayValue(jsonData.banner.raw)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Software:</span>
                        <span class="info-value">${safeDisplayValue(jsonData.banner.software)}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Protocol:</span>
                        <span class="info-value">${safeDisplayValue(jsonData.banner.protocol)}</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Algorithm Summary
    if (jsonData.algorithms) {
        html += `
            <div class="ssh-section">
                <h6>🔐 Cryptographic Algorithms</h6>
                <div class="algorithm-summary">
        `;

        const algTypes = {
            'kex': 'Key Exchange',
            'key': 'Host Key',
            'enc': 'Encryption',
            'mac': 'Message Authentication'
        };

        for (const [type, title] of Object.entries(algTypes)) {
            if (jsonData.algorithms[type] && jsonData.algorithms[type].length > 0) {
                html += `
                    <div class="alg-type">
                        <strong>${title}:</strong> ${jsonData.algorithms[type].length} algorithms
                    </div>
                `;
            }
        }

        html += '</div></div>';
    }

    // Security Recommendations
    if (jsonData.algorithms && jsonData.algorithms.recommendations) {
        const recs = jsonData.algorithms.recommendations;
        html += `
            <div class="ssh-section">
                <h6>⚠️ Security Recommendations</h6>
                <div class="recommendations-grid">
        `;

        if (recs.critical && recs.critical.del && recs.critical.del.length > 0) {
            html += `
                <div class="rec-critical">
                    <strong>🚨 Critical:</strong> Remove ${recs.critical.del.length} weak algorithms
                </div>
            `;
        }

        if (recs.warning && recs.warning.del && recs.warning.del.length > 0) {
            html += `
                <div class="rec-warning">
                    <strong>⚠️ Warning:</strong> Consider removing ${recs.warning.del.length} algorithms
                </div>
            `;
        }

        if ((!recs.critical || !recs.critical.del || recs.critical.del.length === 0) &&
            (!recs.warning || !recs.warning.del || recs.warning.del.length === 0)) {
            html += `
                <div class="rec-good">
                    <strong>✅ Good:</strong> No critical algorithm issues detected
                </div>
            `;
        }

        html += '</div></div>';
    }

    // Additional Notes
    if (jsonData.additional_notes && jsonData.additional_notes.length > 0) {
        html += `
            <div class="ssh-section">
                <h6>📝 Additional Security Notes</h6>
                <div class="notes-list">
        `;

        jsonData.additional_notes.forEach(note => {
            if (note && note.trim()) {
                // Clean up note text
                let cleanNote = note.replace(/Potentially insufficient connection throttling detected, resulting in possible vulnerability to the DHEat DoS attack \(CVE-2002-20001\)\./,
                    'Connection throttling configuration may need adjustment for optimal security');
                html += `<div class="note-item">• ${safeDisplayValue(cleanNote)}</div>`;
            }
        });

        html += '</div></div>';
    }

    html += '</div>';
    return html;
}

// Helper function to render SSH algorithms summary (updated without security score)
function renderSSHAlgorithmsSummary(algorithms) {
    if (!algorithms || Object.keys(algorithms).length === 0) {
        return '<p>No algorithm data available</p>';
    }

    let html = '';

    const algorithmTypes = {
        'kex': '🔑 Key Exchange',
        'key': '🏠 Host Key',
        'enc': '🔒 Encryption',
        'mac': '✅ MAC'
    };

    for (const [type, title] of Object.entries(algorithmTypes)) {
        if (algorithms[type] && algorithms[type].length > 0) {
            const algs = algorithms[type];
            const count = algs.length;

            html += `
                <div class="algorithm-type-section">
                    <div class="algorithm-type-header">
                        <strong>${title}:</strong> 
                        <span class="algorithm-count">${count} algorithms</span>
                    </div>
                </div>
            `;
        }
    }

    return html || '<p>Algorithm analysis completed</p>';
}



// Helper function to format SSH-Audit raw output for better display
function formatSSHAuditRawOutput(rawOutput) {
    try {
        // If it's JSON, format it nicely
        if (rawOutput.trim().startsWith('{')) {
            const jsonData = JSON.parse(rawOutput);
            return JSON.stringify(jsonData, null, 2);
        }
        // Otherwise return as-is
        return rawOutput;
    } catch (e) {
        // If JSON parsing fails, return raw output
        return rawOutput;
    }
}

function renderVulnerabilityItem(vuln, serviceType) {
    if (serviceType === 'http') {
        return renderHTTPVulnerabilityItem(vuln);
    }
    if (serviceType === 'smb') {
        return renderSMBVulnerabilityItem(vuln);
    }
    if (serviceType === 'snmp') {
        return renderSNMPVulnerabilityItem(vuln);
    }
    if (serviceType === 'https') {
        return renderHTTPSVulnerabilityItem(vuln);
    }

    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'scanner';

    // Determine badge type for other services
    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap') || vuln.detection_method?.includes('nmap')) {
        badgeText = 'NMAP';
        badgeClass = 'nmap-badge';
    } else if (source.includes('manual')) {
        badgeText = 'MANUAL';
        badgeClass = 'manual-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass}" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}



// Helper function for nmap-only vulnerability items
function renderNmapVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'nmap_scanner';

    return `
        <div class="vulnerability-item ${severityClass} nmap-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'NMAP-FINDING')}</span>
                    <span class="nmap-badge">NMAP</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
            
            
        </div>
    `;
}


function showDeepFTPScanButton(scanData) {
    // Check if nmap is available for deep scanning
    const nmapAvailable = scanData.nmap_enhanced || scanData.scanner_capabilities?.nmap_available;

    if (!nmapAvailable) {
        console.log('Deep FTP scan not available - nmap not detected');
        return;
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-ftp-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep FTP Scan (All Scripts)</span>
    `;
    deepScanBtn.id = 'deepFTPScanBtn';
    deepScanBtn.onclick = () => startDeepFTPScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        // Remove any existing deep scan button
        const existingBtn = document.getElementById('deepFTPScanBtn');
        if (existingBtn) {
            existingBtn.remove();
        }

        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep FTP Scan button added');
    }
}

async function startDeepFTPScan(previousScanData) {
    console.log('🎯 Starting deep FTP scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(DEEP_SCAN_WARNINGS.ftp.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep FTP scan');
        Utils.showNotification('Deep FTP scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep FTP scan - proceeding...');

    const deepBtn = document.getElementById('deepFTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All FTP Scripts...</span>
        `;
    }

    try {
        showDeepScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'ftp',
            enableCveCheck: true,
            deepScan: true
        };

        console.log('🚀 Starting deep FTP scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep FTP scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep FTP scan results:', deepResults);

        showDeepFTPResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep FTP scan error:', error);
        Utils.showNotification(`Deep FTP scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep FTP Scan (All Scripts)</span>
            `;
        }
    }
}

function showDeepScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'FTP (Deep Scan - All Scripts)';
    }

    updateScanProgress(25, 'Loading comprehensive NSE script suite...');

    setTimeout(() => updateScanProgress(50, 'Running ftp-* scripts...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep findings...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep FTP scan completed'), 3000);
}

function showDeepFTPResults(deepResults, originalResults) {
    console.log('🔍 Showing deep FTP scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep FTP Scan Output
            <span class="deep-scan-badge">Raw Results</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show ONLY raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep FTP Scan Output</h4>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;

        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepFTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    Utils.showNotification('Deep FTP scan completed', 'success');

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

function cancelScan() {
    if (!activeScanInProgress) return;

    activeScanInProgress = false;
    Utils.showNotification('Scan cancelled', 'warning');

    hideScanProgress();
    hideCancelButton();
}

// Import/Export Functions
function openImportModal() {
    console.log('Opening import modal');

    const modal = document.getElementById('importModal');
    if (modal) {
        loadPassiveTargets();
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeImportModal() {
    const modal = document.getElementById('importModal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function loadPassiveTargets() {
    const container = document.getElementById('passiveTargetsList');
    if (!container) return;

    // For demo purposes, show some mock data
    const mockTargets = [
        { ip: '192.168.1.100', port: '22', service: 'ssh', sessionName: 'Test Session 1' },
        { ip: '192.168.1.100', port: '443', service: 'https', sessionName: 'Test Session 1' },
        { ip: '10.0.0.50', port: '25', service: 'smtp', sessionName: 'Test Session 2' }
    ];

    if (mockTargets.length === 0) {
        container.innerHTML = '<p class="no-targets">No passive scan results found with supported ports.<br><small>Supported: SSH (22), SMTP (25), SNMP (161), HTTPS (443), SMB (445)</small></p>';
        return;
    }

    container.innerHTML = mockTargets.map(target => `
        <div class="target-item" data-ip="${target.ip}" data-port="${target.port}">
            <div class="target-checkbox">
                <input type="checkbox" id="import_${target.ip}_${target.port}">
            </div>
            <div class="target-info">
                <div class="target-header">
                    <span class="target-address">${target.ip}:${target.port}</span>
                    <span class="service-badge ${target.service}">${Utils.getServiceType(target.port)}</span>
                </div>
                <div class="target-details">
                    <span class="service-name">${target.service}</span>
                    <span class="service-version"> • From: ${target.sessionName}</span>
                </div>
            </div>
        </div>
    `).join('');

    // Add click handlers for target items
    container.addEventListener('click', function(event) {
        const targetItem = event.target.closest('.target-item');
        if (targetItem && !event.target.matches('input[type="checkbox"]')) {
            const checkbox = targetItem.querySelector('input[type="checkbox"]');
            if (checkbox) {
                checkbox.checked = !checkbox.checked;
                targetItem.classList.toggle('selected', checkbox.checked);
            }
        }
    });
}

function importSelectedTargets() {
    const selectedTargets = document.querySelectorAll('#passiveTargetsList input[type="checkbox"]:checked');

    if (selectedTargets.length === 0) {
        Utils.showNotification('Please select at least one target', 'warning');
        return;
    }

    // Collect selected targets
    const targets = Array.from(selectedTargets).map(checkbox => {
        const item = checkbox.closest('.target-item');
        return {
            ip: item.dataset.ip,
            port: item.dataset.port,
            service: Utils.getServiceType(item.dataset.port)
        };
    });

    // Store in memory
    pendingTargets = [...targets];
    importedTargetsData = [...targets];

    if (targets.length === 1) {
        // Single target - auto-populate manual form
        autoPopulateTarget(targets[0]);
        switchScanMode('manual');
    } else {
        // Multiple targets - set up for batch scan
        showMultipleTargetsSelection();
    }

    closeImportModal();
    Utils.showNotification(`Imported ${targets.length} target${targets.length > 1 ? 's' : ''}`, 'success');
}

function saveActiveScanSession() {
    if (!currentScanData) {
        Utils.showNotification('No scan data to save', 'warning');
        return;
    }

    // Mock save functionality
    const sessionName = `Active Scan - ${currentScanData.target} - ${new Date().toLocaleString()}`;

    try {
        // In real implementation, this would save to localStorage or send to server
        console.log('Saving session:', sessionName, currentScanData);
        Utils.showNotification('Session saved successfully', 'success');
    } catch (error) {
        Utils.handleError(error, 'Save session');
    }
}

function exportActiveScanResults() {
    if (!currentScanData) {
        Utils.showNotification('No scan data to export', 'warning');
        return;
    }

    try {
        const report = generateTextReport(currentScanData);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
        const filename = `active_scan_${currentScanData.target.replace(':', '_')}_${timestamp}.txt`;

        downloadFile(report, filename);
        Utils.showNotification('Results exported successfully', 'success');
    } catch (error) {
        Utils.handleError(error, 'Export results');
    }
}

function generateTextReport(scanData) {
    let report = `Active Scan Report
==================
Target: ${scanData.target}
Service Type: ${scanData.service_type || 'Unknown'}
Scan Time: ${scanData.scan_time ? new Date(scanData.scan_time).toLocaleString() : 'Unknown'}

Service Information
------------------
`;

    if (scanData.service_info) {
        Object.entries(scanData.service_info).forEach(([key, value]) => {
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            report += `${displayKey}: ${value}\n`;
        });
    }

    report += `\nSecurity Assessment
------------------
`;

    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
        scanData.vulnerabilities.forEach(vuln => {
            report += `
Vulnerability: ${vuln.id || 'N/A'}
Severity: ${vuln.severity || 'Unknown'}
Title: ${vuln.title || 'N/A'}
Description: ${vuln.description || 'N/A'}
${vuln.recommendation ? `Recommendation: ${vuln.recommendation}` : ''}
`;
        });
    } else {
        report += 'No immediate security issues detected\n';
    }

    if (scanData.recommendations && scanData.recommendations.length > 0) {
        report += `\nRecommendations
--------------
`;
        scanData.recommendations.forEach((rec, index) => {
            report += `${index + 1}. ${rec}\n`;
        });
    }

    return report;
}

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

// Global functions for onclick handlers (needed for HTML onclick attributes)
window.selectImportedTarget = selectImportedTarget;
window.setupBatchScan = setupBatchScan;

function checkForLoadedSession() {
    console.log('🔍 ACTIVE SCAN: Checking for loaded session...');

    try {
        const urlParams = new URLSearchParams(window.location.search);
        const loaded = urlParams.get('loaded') === 'true';

        if (loaded) {
            const loadedSessionData = sessionStorage.getItem('loadedActiveScan');
            console.log('🔍 ACTIVE SCAN: Raw session data:', loadedSessionData);

            if (loadedSessionData) {
                try {
                    const sessionData = JSON.parse(loadedSessionData);
                    console.log('🔍 ACTIVE SCAN: Parsed session data:', sessionData);

                    // Enhanced form population
                    populateEnhancedFormFromSession(sessionData);

                    // If we have previous scan results, show them with all data
                    if (sessionData.scan_results) {
                        console.log('🔍 ACTIVE SCAN: Loading complete scan results...');
                        currentScanData = sessionData.scan_results;

                        const resultsSection = document.getElementById('scanResults');
                        if (resultsSection) {
                            resultsSection.classList.remove('hidden');
                        }

                        // Enhanced results display
                        showEnhancedScanResults(sessionData.scan_results);
                        Utils.showNotification(`Session loaded with complete results`, 'success');
                    } else {
                        Utils.showNotification(`Session "${sessionData.target}" loaded`, 'success');
                    }

                    // Clean up
                    sessionStorage.removeItem('loadedActiveScan');
                    const newUrl = window.location.pathname;
                    history.replaceState({}, document.title, newUrl);

                } catch (parseError) {
                    console.error('Error parsing session data:', parseError);
                    Utils.showNotification('Error loading session', 'error');
                    sessionStorage.removeItem('loadedActiveScan');
                }
            }
        }
    } catch (error) {
        console.error('Error checking for loaded session:', error);
    }
}

function initializeActiveScan() {
    console.log('Initializing Active Scan...');

    // Setup event listeners
    setupEventListeners();

    // Setup form handlers
    setupScanForm();

    // Setup template cards
    setupTemplateCards();

    // Check for imported targets from session storage
    checkForImportedTargets();

    // Check for loaded session data
    checkForLoadedSession();

    // Update scan description
    updateScanDescription();

    console.log('Active Scan initialized successfully');
}

function hideCancelButton() {
    const cancelButton = document.getElementById('cancelScanBtn');
    if (cancelButton) {
        cancelButton.style.display = 'none';
        console.log('Cancel button hidden - scan completed');
    }
}

function showCancelButton() {
    const cancelButton = document.getElementById('cancelScanBtn');
    if (cancelButton) {
        cancelButton.style.display = 'inline-flex';
        console.log('Cancel button shown - scan in progress');
    }
}

function formatAdvancedFindings(findings, serviceType) {
    let html = '<div class="advanced-findings-content">';

    if (serviceType === 'ftp' && findings.nmap_data) {
        html += formatNmapData(findings.nmap_data);
    }

    if (serviceType === 'snmp') {
        html += formatSNMPAdvancedFindings(findings);
    }

    for (const [key, value] of Object.entries(findings)) {
        if (typeof value === 'object' && value !== null) {
            if (Array.isArray(value) && value.length > 0) {
                html += `
                    <div class="finding-section">
                        <h5>${key.replace(/_/g, ' ').toUpperCase()}</h5>
                        <ul class="finding-list">
                            ${value.slice(0, 10).map(item => {
                                if (typeof item === 'object' && item !== null) {
                                    if (item.path && item.status_code) {
                                        return `<li><strong>${Utils.escapeHtml(item.path)}</strong> - Status: ${item.status_code}</li>`;
                                    }
                                    else if (item.url && item.status) {
                                        return `<li><strong>${Utils.escapeHtml(item.url)}</strong> - Status: ${item.status}</li>`;
                                    }
                                    else if (item.path && item.status) {
                                        return `<li><strong>${Utils.escapeHtml(item.path)}</strong> - Status: ${item.status}</li>`;
                                    }
                                    else if (item.path) {
                                        return `<li><strong>${Utils.escapeHtml(item.path)}</strong></li>`;
                                    }
                                    else if (item.url) {
                                        return `<li><strong>${Utils.escapeHtml(item.url)}</strong></li>`;
                                    }
                                    else {
                                        const entries = Object.entries(item);
                                        const displayEntries = entries.map(([k, v]) => {
                                            let displayValue;
                                            if (typeof v === 'object' && v !== null) {
                                                if (Array.isArray(v)) {
                                                    displayValue = `[${v.length} items]`;
                                                } else {
                                                    displayValue = `{${Object.keys(v).length} props}`;
                                                }
                                            } else {
                                                displayValue = String(v);
                                            }
                                            return `<strong>${k}:</strong> ${Utils.escapeHtml(displayValue)}`;
                                        }).join('<br>');
                                        
                                        return `<li style="background: rgba(255,255,255,0.05); padding: 8px; margin: 4px 0; border-radius: 4px; font-size: 0.9em;">${displayEntries}</li>`;
                                    }
                                } else {
                                    return `<li>${Utils.escapeHtml(String(item))}</li>`;
                                }
                            }).join('')}
                            ${value.length > 10 ? `<li class="more-items">... and ${value.length - 10} more</li>` : ''}
                        </ul>
                    </div>
                `;
            } else if (!Array.isArray(value)) {
                html += `
                    <div class="finding-section">
                        <h5>${key.replace(/_/g, ' ').toUpperCase()}</h5>
                        <div class="finding-details">
                            ${Object.entries(value).map(([k, v]) => `
                                <div class="finding-detail">
                                    <strong>${k}:</strong> ${Utils.escapeHtml(String(v))}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
        } else {
            html += `
                <div class="finding-row">
                    <span class="finding-label">${key.replace(/_/g, ' ')}:</span>
                    <span class="finding-value">${Utils.escapeHtml(String(value))}</span>
                </div>
            `;
        }
    }

    html += '</div>';
    return html;
}

function formatFTPFindings(findings) {
    if (!findings || typeof findings !== 'object') {
        return '<p class="no-ftp-findings">No FTP findings available</p>';
    }

    let html = '<div class="ftp-findings-container">';

    // Anonymous access results
    if (findings.anonymous_access && typeof findings.anonymous_access === 'object') {
        const anonAccess = findings.anonymous_access;
        html += `
            <div class="ftp-finding-card">
                <h4>📁 Anonymous Access Analysis</h4>
                <div class="access-method-${anonAccess.allowed ? 'success' : 'failed'}">
                    Status: ${anonAccess.allowed ? 'ALLOWED' : 'DENIED'}
                </div>
                ${anonAccess.allowed ? `
                    <div class="ftp-details">
                        <p><strong>Readable:</strong> ${safeDisplayValue(anonAccess.readable)}</p>
                        <p><strong>Writable:</strong> ${safeDisplayValue(anonAccess.writable)}</p>
                        ${anonAccess.login_used ? `<p><strong>Login Used:</strong> ${safeDisplayValue(anonAccess.login_used)}</p>` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    }

    // File system information
    if (findings.file_system_info && findings.file_system_info.file_types_found) {
        const fileTypes = findings.file_system_info.file_types_found;
        if (typeof fileTypes === 'object' && Object.keys(fileTypes).length > 0) {
            html += `
                <div class="ftp-finding-card">
                    <h4>📂 File System Analysis</h4>
                    <div class="ftp-file-types">
                        ${Object.entries(fileTypes)
                            .map(([ext, count]) => `<span class="file-type-badge">${ext}: ${safeDisplayValue(count)}</span>`)
                            .join('')}
                    </div>
                </div>
            `;
        }
    }

    // Security tests
    if (findings.security_tests && typeof findings.security_tests === 'object') {
        const secTests = findings.security_tests;
        html += `
            <div class="ftp-finding-card">
                <h4>🔒 Security Assessment</h4>
                <div class="security-tests">
                    ${secTests.directory_traversal !== undefined ? 
                        `<div class="security-${secTests.directory_traversal ? 'critical' : 'good'}">
                            Directory Traversal: ${secTests.directory_traversal ? 'VULNERABLE' : 'PROTECTED'}
                        </div>` : ''}
                    ${secTests.bounce_attack_possible !== undefined ? 
                        `<div class="security-${secTests.bounce_attack_possible ? 'warning' : 'good'}">
                            Bounce Attack: ${secTests.bounce_attack_possible ? 'POSSIBLE' : 'PROTECTED'}
                        </div>` : ''}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function safeDisplayValue(value) {
    // Handle null, undefined, empty
    if (value === null || value === undefined || value === '') {
        return '';
    }

    // Handle strings
    if (typeof value === 'string') {
        return value.trim();
    }

    // Handle numbers
    if (typeof value === 'number') {
        return value.toString();
    }

    // Handle booleans
    if (typeof value === 'boolean') {
        return value ? 'Yes' : 'No';
    }

    // Handle arrays
    if (Array.isArray(value)) {
        if (value.length === 0) return '';

        // If array of simple values, join them
        if (value.every(item => typeof item === 'string' || typeof item === 'number')) {
            return value.slice(0, 3).join(', ') + (value.length > 3 ? ` (+${value.length - 3} more)` : '');
        }

        // For complex arrays, show count
        return `${value.length} items`;
    }

    // Handle objects
    if (typeof value === 'object' && value !== null) {
        // Try to find a meaningful display value
        if (value.name) return safeDisplayValue(value.name);
        if (value.title) return safeDisplayValue(value.title);
        if (value.value) return safeDisplayValue(value.value);
        if (value.text) return safeDisplayValue(value.text);

        // For objects with few properties, show key-value pairs
        const entries = Object.entries(value);
        if (entries.length <= 3) {
            return entries
                .map(([k, v]) => `${k}: ${safeDisplayValue(v)}`)
                .join(', ');
        }

        // Otherwise, show object summary
        return `{${entries.length} properties}`;
    }

    // Fallback - convert to string but avoid [object Object]
    try {
        const stringValue = String(value);
        if (stringValue === '[object Object]') {
            return JSON.stringify(value).substring(0, 50) + '...';
        }
        return stringValue;
    } catch (e) {
        return 'Unable to display value';
    }
}



function renderEnhancedVulnerabilitiesCard(vulnerabilities) {
    let html = `
        <div class="result-card">
            <h4>🛡️ Enhanced Security Assessment</h4>
            <div class="vulnerabilities-section">
    `;

    if (vulnerabilities && vulnerabilities.length > 0) {
        // Vulnerability statistics
        const severityCounts = {
            'Critical': vulnerabilities.filter(v => v.severity === 'Critical').length,
            'High': vulnerabilities.filter(v => v.severity === 'High').length,
            'Medium': vulnerabilities.filter(v => v.severity === 'Medium').length,
            'Low': vulnerabilities.filter(v => v.severity === 'Low').length,
            'Info': vulnerabilities.filter(v => v.severity === 'Info' || v.severity === 'Informational').length
        };

        html += `
            <div class="vulnerabilities-summary">
                <div class="vuln-stats">
                    <div class="vuln-stat critical">
                        <span class="count">${severityCounts.Critical}</span>
                        <span class="label">Critical</span>
                    </div>
                    <div class="vuln-stat high">
                        <span class="count">${severityCounts.High}</span>
                        <span class="label">High</span>
                    </div>
                    <div class="vuln-stat medium">
                        <span class="count">${severityCounts.Medium}</span>
                        <span class="label">Medium</span>
                    </div>
                    <div class="vuln-stat low">
                        <span class="count">${severityCounts.Low}</span>
                        <span class="label">Low</span>
                    </div>
                    <div class="vuln-stat info">
                        <span class="count">${severityCounts.Info}</span>
                        <span class="label">Info</span>
                    </div>
                </div>
            </div>
        `;

        // Vulnerability list
        html += `
            <div class="vulnerabilities-list">
                ${vulnerabilities.map(vuln => renderEnhancedVulnerabilityItem(vuln)).join('')}
            </div>
        `;
    } else {
        html += `
            <div class="no-vulnerabilities">
                <div class="success-icon">✅</div>
                <p>No immediate security issues detected</p>
                <small>This does not guarantee the service is completely secure</small>
            </div>
        `;
    }

    html += `
            </div>
        </div>
    `;

    return html;
}

function renderEnhancedVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const hasExploits = vuln.has_exploits || vuln.source === 'Exploit-DB (Searchsploit)';
    const isSearchsploit = vuln.source === 'Exploit-DB (Searchsploit)';
    const source = vuln.source || 'unknown';

    return `
        <div class="vulnerability-item ${severityClass} ${hasExploits ? 'has-exploits' : ''}" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || vuln.cve_id || 'N/A')}</span>
                    ${isSearchsploit ? 
                        '<span class="exploit-badge">EXPLOIT</span>' : 
                        '<span class="cve-badge">CVE</span>'
                    }
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                    ${vuln.cvss_score ? 
                        `<span class="cvss-score">CVSS: ${vuln.cvss_score}</span>` : ''
                    }
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.exploit_type ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Type:</strong> ${safeDisplayValue(vuln.exploit_type)}
                        </span>
                        ${vuln.platform ? `
                            <span class="metadata-item">
                                <strong>Platform:</strong> ${safeDisplayValue(vuln.platform)}
                            </span>
                        ` : ''}
                    </div>
                ` : ''}
                
                ${vuln.cvss_vector ? `
                    <div class="vuln-cvss">
                        <strong>CVSS Vector:</strong> 
                        <code class="cvss-vector">${safeDisplayValue(vuln.cvss_vector)}</code>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
            
            <div class="vuln-footer">
                <div class="vuln-source">
                    <span class="source-icon">${isSearchsploit ? '💥' : '🛡️'}</span>
                    <span class="source-name">${safeDisplayValue(vuln.source || 'Vulners API')}</span>
                </div>
                ${vuln.confidence ? `
                    <div class="vuln-confidence">
                        <span class="confidence-badge confidence-${vuln.confidence}">
                            ${vuln.confidence} confidence
                        </span>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderFailedScanResults(scanData) {
    const failureInfo = scanData.failure_info || {};
    const primaryReason = failureInfo.primary_reason || scanData.failure_reason || 'Scan failed';
    const suggestions = failureInfo.user_suggestions || [];
    const nextSteps = failureInfo.next_steps || [];

    return `
        <div class="result-card failed-scan">
            <h4>❌ Scan Failed</h4>
            <div class="result-details">
                <div class="detail-row">
                    <span class="detail-label">Target:</span>
                    <span class="detail-value">${safeDisplayValue(scanData.target || `${scanData.ip}:${scanData.port}`)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Service Type:</span>
                    <span class="detail-value">${safeDisplayValue(scanData.service_type || scanData.service_name || 'Unknown').toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Scan Status:</span>
                    <span class="detail-value status-failed">FAILED</span>
                </div>
                ${scanData.scan_duration ? `
                <div class="detail-row">
                    <span class="detail-label">Duration:</span>
                    <span class="detail-value">${scanData.scan_duration}ms</span>
                </div>
                ` : ''}
            </div>
        </div>

        <div class="result-card failure-details">
            <h4>🔍 Failure Analysis</h4>
            <div class="failure-content">
                <div class="failure-reason">
                    <h5>❌ What happened:</h5>
                    <p class="failure-message">${safeDisplayValue(primaryReason)}</p>
                </div>

                ${suggestions.length > 0 ? `
                <div class="failure-suggestions">
                    <h5>💡 Possible causes and solutions:</h5>
                    <ul class="suggestions-list">
                        ${suggestions.map(suggestion => `
                            <li class="suggestion-item">${safeDisplayValue(suggestion)}</li>
                        `).join('')}
                    </ul>
                </div>
                ` : ''}

                ${nextSteps.length > 0 ? `
                <div class="failure-next-steps">
                    <h5>🔧 Next steps to try:</h5>
                    <ul class="next-steps-list">
                        ${nextSteps.map(step => `
                            <li class="next-step-item">${safeDisplayValue(step)}</li>
                        `).join('')}
                    </ul>
                </div>
                ` : ''}

                <div class="failure-tips">
                    <h5>🎯 Quick troubleshooting tips:</h5>
                    <ul class="tips-list">
                        <li>Verify the target IP address and port are correct</li>
                        <li>Check if you have permission to scan this target</li>
                        <li>Ensure your network connection is stable</li>
                        <li>Try scanning a known working target to test your setup</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="result-card retry-section">
            <h4>🔄 Try Again</h4>
            <div class="retry-content">
                <p>Want to try the scan again with different settings?</p>
                <button class="retry-scan-btn" onclick="retryFailedScan()">
                    🔄 Retry Scan
                </button>
                <button class="different-target-btn" onclick="clearAndStartNew()">
                    🎯 Scan Different Target
                </button>
            </div>
        </div>
    `;
}



function hasValidAdvancedFindings(advancedFindings) {
    if (!advancedFindings || typeof advancedFindings !== 'object') return false;

    // Exclude status-only objects
    const excludeKeys = ['scan_status'];
    const meaningfulKeys = Object.keys(advancedFindings).filter(key =>
        !excludeKeys.includes(key) &&
        advancedFindings[key] !== null &&
        advancedFindings[key] !== undefined &&
        advancedFindings[key] !== ''
    );

    return meaningfulKeys.length > 0;
}

function retryFailedScan() {
    if (currentScanData && currentScanData.ip && currentScanData.port) {
        // Clear previous results
        const resultsSection = document.getElementById('scanResults');
        if (resultsSection) {
            resultsSection.classList.add('hidden');
        }

        // Get current form values
        const targetIPInput = document.getElementById('targetIP');
        const targetPortInput = document.getElementById('targetPort');
        const scanTypeSelect = document.getElementById('scanType');

        // Use current form values or fallback to previous scan data
        const retryConfig = {
            targetIP: targetIPInput?.value || currentScanData.ip,
            targetPort: parseInt(targetPortInput?.value || currentScanData.port),
            scanType: scanTypeSelect?.value || 'auto'
        };

        console.log('🔄 Retrying scan with config:', retryConfig);
        Utils.showNotification('Retrying scan...', 'info');

        startActiveScan(retryConfig);
    } else {
        Utils.showNotification('Cannot retry - missing scan data', 'error');
    }
}

function clearAndStartNew() {
    // Clear previous results
    const resultsSection = document.getElementById('scanResults');
    if (resultsSection) {
        resultsSection.classList.add('hidden');
    }

    // Clear form fields if they exist
    const ipInput = document.getElementById('targetIP');
    const portInput = document.getElementById('targetPort');
    const scanTypeSelect = document.getElementById('scanType');

    if (ipInput) ipInput.value = '';
    if (portInput) portInput.value = '';
    if (scanTypeSelect) scanTypeSelect.value = 'auto';

    // Clear current scan data
    currentScanData = null;

    // Focus on IP input for new scan
    if (ipInput) ipInput.focus();

    // Switch to manual mode
    switchScanMode('manual');

    console.log('🎯 Starting new scan session');
    Utils.showNotification('Ready for new scan', 'info');
}

function formatEnhancedServiceInfo(serviceInfo, serviceType) {
    let html = '';

    // Always show basic service information first (NO SHODAN FIELDS)
    if (serviceInfo.service_name || serviceType) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Type:</span>
                <span class="service-value">${serviceInfo.service_name || serviceType.toUpperCase()}</span>
            </div>
        `;
    }

    if (serviceInfo.service_version || serviceInfo.version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Version:</span>
                <span class="service-value">${serviceInfo.service_version || serviceInfo.version}</span>
            </div>
        `;
    }

    if (serviceInfo.banner) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Banner:</span>
                <span class="service-value banner-text">${safeDisplayValue(serviceInfo.banner)}</span>
            </div>
        `;
    }

    // Handle response time
    if (serviceInfo.response_time_ms || serviceInfo.connection_time) {
        const responseTime = serviceInfo.response_time_ms || serviceInfo.connection_time;
        html += `
            <div class="service-detail-row">
                <span class="service-label">Response Time:</span>
                <span class="service-value">${responseTime}ms</span>
            </div>
        `;
    }

    if (serviceInfo.accessible !== undefined) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Accessible:</span>
                <span class="service-value">${serviceInfo.accessible ? '✅ Yes' : '❌ No'}</span>
            </div>
        `;
    }

    // Only add remaining fields if they're simple values (SKIP ALL SHODAN FIELDS)
    for (const [key, value] of Object.entries(serviceInfo)) {
        const skipKeys = [
            'service_name', 'service_version', 'version', 'banner', 'response_time_ms',
            'accessible', 'scan_failed', 'port_status', 'connection_time', 'error',
            // REMOVED ALL SHODAN REFERENCES
        ];

        if (skipKeys.includes(key) || value === null || value === undefined || value === '') {
            continue;
        }

        // Only include simple values to avoid [object Object]
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            let displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            let displayValue = typeof value === 'boolean' ? (value ? '✅ Yes' : '❌ No') : value;

            html += `
                <div class="service-detail-row">
                    <span class="service-label">${displayKey}:</span>
                    <span class="service-value">${safeDisplayValue(displayValue)}</span>
                </div>
            `;
        }
    }

    // Fallback content if nothing was added
    if (!html.trim()) {
        html = `
            <div class="service-detail-row">
                <span class="service-label">Service Detected:</span>
                <span class="service-value">${serviceType.toUpperCase()} service is running</span>
            </div>
            <div class="service-detail-row">
                <span class="service-label">Port Status:</span>
                <span class="service-value">✅ Open and Accessible</span>
            </div>
        `;
    }

    return html;
}

function populateEnhancedFormFromSession(sessionData) {
    console.log('🔍 ACTIVE SCAN: populateEnhancedFormFromSession with:', sessionData);

    try {
        // Switch to manual mode
        switchScanMode('manual');

        // Fill in ALL form fields
        const targetIPInput = document.getElementById('targetIP');
        const targetPortInput = document.getElementById('targetPort');
        const scanTypeSelect = document.getElementById('scanType');
        const enableCveCheckbox = document.getElementById('enableCveCheck');
        const customWordlistInput = document.getElementById('customWordlist');

        // Populate basic fields
        if (targetIPInput && sessionData.targetIP) {
            targetIPInput.value = sessionData.targetIP;
            console.log('✅ Set target IP:', sessionData.targetIP);
        }

        if (targetPortInput && sessionData.targetPort) {
            targetPortInput.value = sessionData.targetPort;
            console.log('✅ Set target port:', sessionData.targetPort);
        }

        if (scanTypeSelect && sessionData.scanType) {
            scanTypeSelect.value = sessionData.scanType;
            console.log('✅ Set scan type:', sessionData.scanType);
        }

        // Enhanced CVE checkbox handling
        if (enableCveCheckbox) {
            const cveEnabled = sessionData.enableCveCheck !== undefined ? sessionData.enableCveCheck : true;
            enableCveCheckbox.checked = cveEnabled;
            enableCveCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
            console.log('✅ Set CVE checking:', cveEnabled);
        }

        // Handle custom wordlist if present
        if (customWordlistInput && sessionData.customWordlist) {
            customWordlistInput.value = sessionData.customWordlist;
            console.log('✅ Set custom wordlist:', sessionData.customWordlist.split('\n').length, 'lines');
        }

        // Update the description and trigger form validation
        updateScanDescription();

        // Trigger validation on all inputs
        [targetIPInput, targetPortInput].forEach(input => {
            if (input) {
                input.dispatchEvent(new Event('input'));
                input.dispatchEvent(new Event('blur'));
            }
        });

        // Visual feedback with enhanced styling
        setTimeout(() => {
            [targetIPInput, targetPortInput, scanTypeSelect].forEach(input => {
                if (input) {
                    input.style.boxShadow = '0 0 0 4px rgba(16, 185, 129, 0.3)';
                    input.style.borderColor = '#10b981';
                    setTimeout(() => {
                        input.style.boxShadow = '';
                        input.style.borderColor = '';
                    }, 2000);
                }
            });
        }, 500);

        Utils.showNotification('Session configuration loaded with all data', 'success');
        console.log('✅ Enhanced form populated successfully');

    } catch (error) {
        console.error('Error populating enhanced form:', error);
        Utils.showNotification('Error loading form data', 'error');
    }
}

function showEnhancedScanResults(scanData) {
    console.log('🔍 ACTIVE SCAN: showEnhancedScanResults with complete data:', scanData);

    const resultsSection = document.getElementById('scanResults');
    const resultsContent = document.getElementById('resultsContent');

    if (!resultsSection || !resultsContent) return;

    hideCancelButton();
    currentScanData = scanData;
    resultsSection.classList.remove('hidden');

    // Build comprehensive results HTML with ALL data (NO SHODAN)
    let resultsHTML = renderCompleteServiceInfo(scanData);
    resultsHTML += renderCompleteTechnicalAnalysis(scanData);

    // Add all conditional sections with their data
    if (scanData.cve_analysis && hasValidCVEData(scanData.cve_analysis)) {
        resultsHTML += renderCVEAnalysisCard(scanData.cve_analysis);
    }

    if (scanData.advanced_findings && hasValidAdvancedFindings(scanData.advanced_findings)) {
        resultsHTML += renderAdvancedFindingsCard(scanData.advanced_findings, scanData.service_type);
    }

    const vulnerabilities = scanData.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
        resultsHTML += renderEnhancedVulnerabilitiesCard(vulnerabilities);
    }

    if (scanData.recommendations && scanData.recommendations.length > 0) {
        resultsHTML += renderRecommendationsCard(scanData.recommendations);
    }

    resultsContent.innerHTML = resultsHTML;

    // Scroll to results
    setTimeout(() => {
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }, 300);

    console.log('✅ ACTIVE SCAN: Enhanced results displayed with all data');
}

function renderCompleteServiceInfo(scanData) {
    const serviceInfo = scanData.service_info || {};
    const scanSummary = scanData.scan_summary || {};

    return `
        <div class="result-card">
            <h4>🎯 Complete Service Information</h4>
            <div class="result-details">
                <div class="detail-row">
                    <span class="detail-label">Target:</span>
                    <span class="detail-value">${safeDisplayValue(scanData.target || `${scanData.ip}:${scanData.port}`)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Service Type:</span>
                    <span class="detail-value">${safeDisplayValue(scanData.service_type || scanData.service_name || 'Unknown').toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Scan Status:</span>
                    <span class="detail-value status-${scanData.status || 'unknown'}">
                        ${safeDisplayValue(scanData.status || 'Unknown').toUpperCase()}
                    </span>
                </div>
                ${serviceInfo.service_version ? `
                <div class="detail-row">
                    <span class="detail-label">Service Version:</span>
                    <span class="detail-value">${safeDisplayValue(serviceInfo.service_version)}</span>
                </div>
                ` : ''}
                ${scanData.banner ? `
                <div class="detail-row">
                    <span class="detail-label">Service Banner:</span>
                    <span class="detail-value banner-text">${safeDisplayValue(scanData.banner)}</span>
                </div>
                ` : ''}
                ${scanSummary.scan_duration ? `
                <div class="detail-row">
                    <span class="detail-label">Scan Duration:</span>
                    <span class="detail-value">${safeDisplayValue(scanSummary.scan_duration)}</span>
                </div>
                ` : ''}
                ${scanSummary.total_vulnerabilities !== undefined ? `
                <div class="detail-row">
                    <span class="detail-label">Total Vulnerabilities:</span>
                    <span class="detail-value vuln-count">${scanSummary.total_vulnerabilities}</span>
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderCompleteTechnicalAnalysis(scanData) {
    const serviceInfo = scanData.service_info || {};

    return `
        <div class="result-card">
            <h4>🔍 Complete Technical Analysis</h4>
            <div class="service-details">
                ${formatEnhancedServiceInfo(serviceInfo, scanData.service_type || 'unknown')}
            </div>
        </div>
    `;
}

function renderAdvancedFindingsCard(findings, serviceType) {
    if (!findings || typeof findings !== 'object') {
        return '';
    }

    // Check if there are meaningful findings
    const meaningfulFindings = Object.keys(findings).filter(key =>
        findings[key] !== null &&
        findings[key] !== undefined &&
        findings[key] !== '' &&
        key !== 'scan_status'
    );

    if (meaningfulFindings.length === 0) {
        return '';
    }

    return `
        <div class="result-card">
            <h4>🚀 Advanced Findings</h4>
            <div class="advanced-findings">
                ${formatAdvancedFindings(findings, serviceType)}
            </div>
        </div>
    `;
}

function renderRecommendationsCard(recommendations) {
    if (!recommendations || !Array.isArray(recommendations) || recommendations.length === 0) {
        return '';
    }

    return `
        <div class="result-card">
            <h4>💡 Security Recommendations</h4>
            <div class="recommendations-list">
                ${recommendations.map((rec, index) => `
                    <div class="recommendation-item">
                        <span class="rec-number">${index + 1}</span>
                        <span class="rec-text">${safeDisplayValue(rec)}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

async function checkNmapCapabilities() {
    try {
        console.log('Checking nmap capabilities...');
        const response = await fetch('/api/integration-status');
        const status = await response.json();

        nmapCapabilities = {
            available: status.integrations?.enhanced_nmap?.enabled || false,
            nse_scripts: status.integrations?.enhanced_nmap?.enabled || false,
            vulners_integration: status.integrations?.enhanced_vulnerability_checking?.enabled || false
        };

        updateNmapUI();
        console.log('Nmap capabilities:', nmapCapabilities);
    } catch (error) {
        console.error('Error checking nmap capabilities:', error);
        nmapCapabilities.available = false;
        updateNmapUI();
    }
}

function updateNmapUI() {
    const nmapToggle = document.getElementById('useEnhancedNmap');
    const nmapStatus = document.getElementById('nmapStatus');
    const enhancedScanInfo = document.getElementById('enhancedScanInfo');

    if (nmapToggle) {
        nmapToggle.disabled = !nmapCapabilities.available;
        nmapToggle.checked = nmapCapabilities.available;
    }

    if (nmapStatus) {
        nmapStatus.className = `nmap-status ${nmapCapabilities.available ? 'available' : 'unavailable'}`;
        nmapStatus.innerHTML = `
            <div class="status-header">
                <span class="status-icon">${nmapCapabilities.available ? '🎯' : '⚠️'}</span>
                <span class="status-text">Enhanced Nmap ${nmapCapabilities.available ? 'Available' : 'Unavailable'}</span>
            </div>
            <div class="status-details">
                <div class="capability">NSE Scripts: ${nmapCapabilities.nse_scripts ? '✅' : '❌'}</div>
                <div class="capability">Vulners Integration: ${nmapCapabilities.vulners_integration ? '✅' : '❌'}</div>
            </div>
        `;
    }

    if (enhancedScanInfo) {
        enhancedScanInfo.style.display = nmapCapabilities.available ? 'block' : 'none';
    }
}

// SSH Scanner JavaScript Functions - Add to active-scan.js

// Helper functions for SSH security scoring
function getScoreClass(score) {
    if (score >= 80) return 'high';
    if (score >= 60) return 'medium';
    return 'low';
}

function getScoreDescription(score) {
    if (score >= 90) return 'Excellent security configuration with minimal issues';
    if (score >= 80) return 'Good security with some minor improvements needed';
    if (score >= 60) return 'Fair security with several issues to address';
    if (score >= 40) return 'Poor security configuration requiring immediate attention';
    return 'Critical security issues requiring urgent remediation';
}
// Show Deep SSH Scan Button
function showDeepSSHScanButton(scanData) {
    // Check if nmap is available for deep scanning
    const nmapAvailable = scanData.nmap_enhanced || scanData.scanner_capabilities?.nmap_available;

    if (!nmapAvailable) {
        console.log('Deep SSH scan not available - nmap not detected');
        return;
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-ssh-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep SSH Scan (All Scripts)</span>
    `;
    deepScanBtn.id = 'deepSSHScanBtn';
    deepScanBtn.onclick = () => startDeepSSHScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        const existingBtn = document.getElementById('deepSSHScanBtn');
        if (existingBtn) {
            existingBtn.remove();
        }

        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep SSH Scan button added');
    }
}

// Start Deep SSH Scan
async function startDeepSSHScan(previousScanData) {
    console.log('🎯 Starting deep SSH scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(DEEP_SCAN_WARNINGS.ssh.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep SSH scan');
        Utils.showNotification('Deep SSH scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep SSH scan - proceeding...');

    const deepBtn = document.getElementById('deepSSHScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All SSH Scripts...</span>
        `;
    }

    try {
        showDeepSSHScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'ssh',
            deepScan: true
        };

        console.log('🚀 Starting deep SSH scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep SSH scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep SSH scan results:', deepResults);

        showDeepSSHResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep SSH scan error:', error);
        Utils.showNotification(`Deep SSH scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep SSH Scan (All Scripts)</span>
            `;
        }
    }
}

// Show Deep SSH Scan Progress
function showDeepSSHScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'SSH (Deep Scan - All Scripts)';
    }

    updateScanProgress(25, 'Loading comprehensive SSH NSE script suite...');

    setTimeout(() => updateScanProgress(50, 'Running ssh-* scripts...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep SSH findings...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep SSH scan completed'), 3000);
}

function showDeepSSHResults(deepResults, originalResults) {
    console.log('🔍 Showing deep SSH scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep SSH Scan Output
            <span class="deep-scan-badge">Raw Results</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show ONLY raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep SSH Scan Output</h4>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;

        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepSSHScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    Utils.showNotification('Deep SSH scan completed', 'success');

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}





function addSSHAuditResultsDisplay(scanData) {
    let resultsHTML = '';

    // SSH-AUDIT RESULTS DISPLAY - Priority display for SSH scans
    if (scanData.service_type === 'ssh' && scanData.ssh_audit_data) {
        if (scanData.ssh_audit_data.error) {
            resultsHTML += `
                <div class="result-card">
                    <h4>🔐 SSH-Audit Scan Status</h4>
                    <div class="ssh-audit-error">
                        <p>SSH-audit scan failed: ${safeDisplayValue(scanData.ssh_audit_data.error)}</p>
                        <small>Scanner used fallback methods for analysis</small>
                    </div>
                </div>
            `;
        } else {
            resultsHTML += `
                <div class="result-card">
                    <h4>🔐 SSH-Audit Security Assessment</h4>
                    <div class="ssh-audit-display">
                        <div class="ssh-audit-command">
                            <strong>Tool:</strong> ${scanData.ssh_audit_data.command_used || 'ssh-audit --json ' + scanData.ip + ':' + scanData.port}
                        </div>
                        
                        ${scanData.ssh_audit_data.security_score !== undefined ? `
                            <div class="ssh-security-score">
                                <div class="security-score-number ${getScoreClass(scanData.ssh_audit_data.security_score)}">
                                    ${scanData.ssh_audit_data.security_score}
                                </div>
                                <div class="security-score-text">
                                    <div class="security-score-label">Security Score</div>
                                    <div class="security-score-description">${getScoreDescription(scanData.ssh_audit_data.security_score)}</div>
                                </div>
                            </div>
                        ` : ''}
                        
                        <div class="ssh-audit-output">
                            <h6>📋 Key Security Findings:</h6>
                            <pre class="ssh-audit-formatted">${scanData.ssh_audit_data.formatted_for_display || 'No formatted output available'}</pre>
                            
                            ${scanData.ssh_audit_data.algorithms && Object.keys(scanData.ssh_audit_data.algorithms).length > 0 ? `
                                <div class="ssh-algorithms-summary">
                                    <h6>🔍 Algorithm Analysis:</h6>
                                    ${Object.entries(scanData.ssh_audit_data.algorithms).map(([type, algs]) => `
                                        <div class="algorithm-section">
                                            <h7>${type.replace('_', ' ').toUpperCase()}:</h7>
                                            ${algs.slice(0, 3).map(alg => `
                                                <div class="algorithm-result ${alg.status}">
                                                    <strong>${alg.algorithm}:</strong> ${alg.status.toUpperCase()} - ${safeDisplayValue(alg.description)}
                                                </div>
                                            `).join('')}
                                            ${algs.length > 3 ? `<div class="algorithm-more">... and ${algs.length - 3} more</div>` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                            
                            <details class="ssh-audit-full-output">
                                <summary>🔍 View Full SSH-Audit Output</summary>
                                <pre class="ssh-audit-raw">${scanData.ssh_audit_data.raw_output || 'No raw output available'}</pre>
                            </details>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    return resultsHTML;


}


function parseSSHAuditOutput(output) {
    const parsed = {
        general: {},
        algorithms: {
            kex: [],
            hostKey: [],
            encryption: [],
            mac: []
        },
        vulnerabilities: [],
        recommendations: [],
        securityScore: 100,
        summary: {}
    };

    if (!output || typeof output !== 'string') {
        return parsed;
    }

    const lines = output.split('\n');
    let currentSection = null;

    for (const line of lines) {
        const trimmed = line.trim();

        // Parse general information
        if (trimmed.startsWith('(gen) banner:')) {
            parsed.general.banner = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) software:')) {
            parsed.general.software = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) compatibility:')) {
            parsed.general.compatibility = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) compression:')) {
            parsed.general.compression = trimmed.split(':', 2)[1]?.trim() || '';
        }

        // Detect algorithm sections
        else if (trimmed.includes('key exchange algorithms')) {
            currentSection = 'kex';
        } else if (trimmed.includes('host-key algorithms')) {
            currentSection = 'hostKey';
        } else if (trimmed.includes('encryption algorithms')) {
            currentSection = 'encryption';
        } else if (trimmed.includes('message authentication code')) {
            currentSection = 'mac';
        } else if (trimmed.includes('algorithm recommendations')) {
            currentSection = 'recommendations';
        } else if (trimmed.startsWith('#')) {
            currentSection = null;
        }

        // Parse algorithm lines
        else if (currentSection && trimmed.startsWith('(')) {
            if (currentSection !== 'recommendations') {
                const algorithm = parseAlgorithmLine(trimmed);
                if (algorithm) {
                    parsed.algorithms[currentSection].push(algorithm);

                    // Calculate security impact
                    if (algorithm.status === 'fail') {
                        parsed.securityScore -= 15;
                        parsed.vulnerabilities.push(createVulnerabilityFromAlgorithm(algorithm, currentSection));
                    } else if (algorithm.status === 'warn') {
                        parsed.securityScore -= 8;
                    }
                }
            } else if (trimmed.startsWith('(rec)')) {
                const rec = trimmed.substring(5).trim();
                if (rec) {
                    parsed.recommendations.push(rec);
                }
            }
        }
    }

    // Ensure minimum score
    parsed.securityScore = Math.max(parsed.securityScore, 0);

    // Generate summary
    parsed.summary = generateSecuritySummary(parsed);

    return parsed;
}

function parseAlgorithmLine(line) {
    try {
        // Match pattern: (type) algorithm-name -- [status] description
        const match = line.match(/\((\w+)\)\s+([^\s]+)\s+--\s+\[(\w+)\]\s+(.+)/);
        if (!match) return null;

        const [, type, name, status, description] = match;

        return {
            type,
            name: name.trim(),
            status: status.toLowerCase(),
            description: description.trim(),
            severity: getAlgorithmSeverity(status, description)
        };
    } catch (e) {
        console.warn('Failed to parse algorithm line:', line, e);
        return null;
    }
}

function getAlgorithmSeverity(status, description) {
    const desc = description.toLowerCase();

    if (status === 'fail' || status === 'FAIL') {
        if (desc.includes('broken') || desc.includes('attack') || desc.includes('collision')) {
            return 'Critical';
        }
        if (desc.includes('weak') || desc.includes('vulnerable')) {
            return 'High';
        }
        return 'High';
    } else if (status === 'warn' || status === 'WARN') {
        if (desc.includes('deprecated') || desc.includes('legacy')) {
            return 'Medium';
        }
        if (desc.includes('weak') || desc.includes('small')) {
            return 'Medium';
        }
        return 'Low';
    }
    return 'Info';
}

function createVulnerabilityFromAlgorithm(algorithm, type) {
    const typeNames = {
        kex: 'Key Exchange',
        hostKey: 'Host Key',
        encryption: 'Encryption',
        mac: 'MAC'
    };

    const vulnId = `SSH-${type.toUpperCase()}-${algorithm.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

    return {
        id: vulnId,
        severity: algorithm.severity || 'Medium',
        title: `Weak ${typeNames[type] || type} Algorithm: ${algorithm.name}`,
        description: algorithm.description || `The ${algorithm.name} algorithm has known security weaknesses and should be disabled.`,
        recommendation: getAlgorithmRecommendation(algorithm.name, type),
        type: 'algorithm_weakness',
        algorithm: algorithm.name,
        algorithmType: type,
        source: 'ssh_audit',
        detection_method: 'ssh-audit cryptographic analysis'
    };
}

function getAlgorithmRecommendation(algorithmName, type) {
    const recommendations = {
        kex: 'Disable weak key exchange algorithms and use modern alternatives like curve25519-sha256 or diffie-hellman-group16-sha512',
        hostKey: 'Replace with ed25519 or rsa-sha2-256/512 host key algorithms',
        encryption: 'Use strong encryption algorithms like AES-CTR or ChaCha20-Poly1305',
        mac: 'Configure HMAC-SHA2-256 or HMAC-SHA2-512 MAC algorithms'
    };

    const specificRecommendations = {
        // Key Exchange
        'diffie-hellman-group1-sha1': 'Replace with diffie-hellman-group16-sha512 or curve25519-sha256',
        'diffie-hellman-group14-sha1': 'Upgrade to diffie-hellman-group14-sha256',

        // Encryption
        'aes128-cbc': 'Replace with aes128-ctr or aes128-gcm@openssh.com',
        'aes192-cbc': 'Replace with aes192-ctr',
        'aes256-cbc': 'Replace with aes256-ctr or chacha20-poly1305@openssh.com',
        '3des-cbc': 'Remove immediately - extremely weak encryption',

        // MAC
        'hmac-sha1': 'Replace with hmac-sha2-256 or hmac-sha2-512',
        'hmac-md5': 'Remove immediately - MD5 is cryptographically broken',

        // Host Key
        'ssh-dss': 'Replace with ssh-ed25519 or rsa-sha2-512',
        'ssh-rsa': 'Upgrade to rsa-sha2-256 or rsa-sha2-512'
    };

    return specificRecommendations[algorithmName] || recommendations[type] ||
           `Disable ${algorithmName} and configure stronger alternatives`;
}

// Generate security summary
function generateSecuritySummary(parsed) {
    const allAlgorithms = Object.values(parsed.algorithms).flat();
    const failed = allAlgorithms.filter(a => a.status === 'fail').length;
    const warned = allAlgorithms.filter(a => a.status === 'warn').length;

    return {
        totalAlgorithms: allAlgorithms.length,
        failedAlgorithms: failed,
        warnedAlgorithms: warned,
        securityLevel: getSecurityLevel(parsed.securityScore),
        majorIssues: failed,
        minorIssues: warned
    };
}

function renderSSHAuditResults(parsedData) {
    return `
        <div class="ssh-audit-professional">
            ${renderSecurityOverview(parsedData)}
            ${renderGeneralInfo(parsedData.general)}
            ${renderAlgorithmAnalysis(parsedData.algorithms)}
            ${renderVulnerabilities(parsedData.vulnerabilities)}
            ${renderRecommendations(parsedData.recommendations)}
        </div>
    `;
}

function renderSecurityOverview(data) {
    const scoreClass = getScoreClass(data.securityScore);
    const level = data.summary.securityLevel;

    return `
        <div class="security-overview-card">
            <div class="security-score-section">
                <div class="security-score ${scoreClass}">
                    <div class="score-number">${data.securityScore}</div>
                    <div class="score-label">Security Score</div>
                </div>
                <div class="security-level">
                    <div class="level-badge ${scoreClass}">${level}</div>
                    <div class="level-description">${getScoreDescription(data.securityScore)}</div>
                </div>
            </div>
            
            <div class="security-stats">
                <div class="stat-item">
                    <div class="stat-number">${data.summary.totalAlgorithms}</div>
                    <div class="stat-label">Total Algorithms</div>
                </div>
                <div class="stat-item critical">
                    <div class="stat-number">${data.summary.failedAlgorithms}</div>
                    <div class="stat-label">Failed</div>
                </div>
                <div class="stat-item warning">
                    <div class="stat-number">${data.summary.warnedAlgorithms}</div>
                    <div class="stat-label">Warnings</div>
                </div>
                <div class="stat-item info">
                    <div class="stat-number">${data.vulnerabilities.length}</div>
                    <div class="stat-label">Issues Found</div>
                </div>
            </div>
        </div>
    `;
}

function renderGeneralInfo(general) {
    return `
        <div class="general-info-card">
            <h4>📋 SSH Server Information</h4>
            <div class="info-grid">
                <div class="info-row">
                    <span class="info-label">Server Banner:</span>
                    <span class="info-value">${general.banner || 'Not available'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Software:</span>
                    <span class="info-value">${general.software || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Compatibility:</span>
                    <span class="info-value">${general.compatibility || 'Unknown'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Compression:</span>
                    <span class="info-value">${general.compression || 'Unknown'}</span>
                </div>
            </div>
        </div>
    `;
}

// Render algorithm analysis by category
function renderAlgorithmAnalysis(algorithms) {
    let html = '<div class="algorithm-analysis-card"><h4>🔐 Algorithm Analysis</h4>';

    const sections = [
        { key: 'kex', title: 'Key Exchange', icon: '🔑' },
        { key: 'hostKey', title: 'Host Key', icon: '🏠' },
        { key: 'encryption', title: 'Encryption', icon: '🔒' },
        { key: 'mac', title: 'MAC', icon: '✅' }
    ];

    for (const section of sections) {
        const algs = algorithms[section.key] || [];
        if (algs.length === 0) continue;

        html += `
            <div class="algorithm-section">
                <h5>${section.icon} ${section.title} Algorithms</h5>
                <div class="algorithm-list">
        `;

        // Show critical issues first, then warnings, then a few good ones
        const failed = algs.filter(a => a.status === 'fail');
        const warned = algs.filter(a => a.status === 'warn');
        const good = algs.filter(a => a.status === 'info').slice(0, 3);

        [...failed, ...warned, ...good].forEach(alg => {
            html += `
                <div class="algorithm-item ${alg.status}">
                    <div class="algorithm-header">
                        <span class="algorithm-name">${alg.name}</span>
                        <span class="algorithm-status ${alg.status}">${alg.status.toUpperCase()}</span>
                    </div>
                    <div class="algorithm-description">${alg.description}</div>
                </div>
            `;
        });

        if (algs.length > failed.length + warned.length + 3) {
            html += `<div class="algorithm-more">... and ${algs.length - failed.length - warned.length - 3} more algorithms</div>`;
        }

        html += '</div></div>';
    }

    html += '</div>';
    return html;
}

// Render vulnerabilities section
function renderVulnerabilities(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        return `
            <div class="vulnerabilities-card">
                <h4>🛡️ Security Issues</h4>
                <div class="no-vulnerabilities">
                    <div class="success-icon">✅</div>
                    <p>No critical algorithm vulnerabilities detected</p>
                </div>
            </div>
        `;
    }

    return `
        <div class="vulnerabilities-card">
            <h4>🛡️ Security Issues (${vulnerabilities.length})</h4>
            <div class="vulnerabilities-list">
                ${vulnerabilities.map(vuln => `
                    <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
                        <div class="vuln-header">
                            <span class="vuln-title">${vuln.title}</span>
                            <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        </div>
                        <div class="vuln-description">${vuln.description}</div>
                        <div class="vuln-recommendation">
                            <strong>Recommendation:</strong> ${vuln.recommendation}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

// Render recommendations section
function renderRecommendations(recommendations) {
    if (recommendations.length === 0) return '';

    return `
        <div class="recommendations-card">
            <h4>💡 Security Recommendations</h4>
            <div class="recommendations-list">
                ${recommendations.map((rec, index) => `
                    <div class="recommendation-item">
                        <span class="rec-number">${index + 1}</span>
                        <span class="rec-text">${rec}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}





function renderSSHAuditError(error) {
    return `
        <div class="result-card ssh-audit-error">
            <h4>🔐 SSH Security Assessment Status</h4>
            <div class="error-content">
                <div class="error-icon">⚠️</div>
                <div class="error-details">
                    <p><strong>SSH-audit scan encountered an issue:</strong></p>
                    <p class="error-message">${safeDisplayValue(error)}</p>
                    <p class="error-note"><em>Scanner used fallback methods for SSH analysis</em></p>
                </div>
            </div>
        </div>
    `;
}




function getSecurityLevel(analysis) {
    if (analysis.weakAlgorithms === 0 && analysis.deprecatedAlgorithms === 0) {
        return 'Excellent';
    } else if (analysis.weakAlgorithms === 0 && analysis.deprecatedAlgorithms <= 2) {
        return 'Good';
    } else if (analysis.weakAlgorithms <= 2) {
        return 'Fair';
    } else {
        return 'Poor';
    }
}

function getOverallStatus(analysis) {
    if (analysis.weakAlgorithms === 0) {
        return 'secure';
    } else if (analysis.weakAlgorithms <= 2) {
        return 'warning';
    } else {
        return 'critical';
    }
}



function renderSSHVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'ssh_scanner';

    let badgeText = 'SSH ANALYSIS';
    let badgeClass = 'ssh-analysis-badge';

    if (source.includes('ssh_audit') || source.includes('ssh-audit')) {
        badgeText = 'SSH-AUDIT';
        badgeClass = 'ssh-audit-badge';
    } else if (source.includes('nmap')) {
        badgeText = 'NMAP';
        badgeClass = 'nmap-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} ssh-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'SSH-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'SSH Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.algorithmType && vuln.algorithm ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Algorithm Type:</strong> ${safeDisplayValue(vuln.algorithmType)}
                        </span>
                        <span class="metadata-item">
                            <strong>Algorithm:</strong> <code>${safeDisplayValue(vuln.algorithm)}</code>
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}



function formatSSHServiceInfo(serviceInfo, serviceType) {
    let html = '';

    // Basic SSH service information
    if (serviceInfo.service_name || serviceType) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Type:</span>
                <span class="service-value">${serviceInfo.service_name || serviceType.toUpperCase()}</span>
            </div>
        `;
    }

    if (serviceInfo.server_type || serviceInfo.ssh_version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SSH Server:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.server_type || serviceInfo.ssh_version)}</span>
            </div>
        `;
    }

    if (serviceInfo.version || serviceInfo.service_version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Version:</span>
                <span class="service-value">${serviceInfo.version || serviceInfo.service_version}</span>
            </div>
        `;
    }

    if (serviceInfo.banner) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SSH Banner:</span>
                <span class="service-value banner-text">${safeDisplayValue(serviceInfo.banner)}</span>
            </div>
        `;
    }

    if (serviceInfo.protocol_version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Protocol Version:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.protocol_version)}</span>
            </div>
        `;
    }

    if (serviceInfo.authentication_methods && Array.isArray(serviceInfo.authentication_methods)) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Auth Methods:</span>
                <span class="service-value">${serviceInfo.authentication_methods.join(', ')}</span>
            </div>
        `;
    }

    // Response time
    if (serviceInfo.response_time_ms || serviceInfo.connection_time) {
        const responseTime = serviceInfo.response_time_ms || serviceInfo.connection_time;
        html += `
            <div class="service-detail-row">
                <span class="service-label">Response Time:</span>
                <span class="service-value">${responseTime}ms</span>
            </div>
        `;
    }

    if (serviceInfo.accessible !== undefined) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Accessible:</span>
                <span class="service-value">${serviceInfo.accessible ? '✅ Yes' : '❌ No'}</span>
            </div>
        `;
    }

    // Fallback content if nothing was added
    if (!html.trim()) {
        html = `
            <div class="service-detail-row">
                <span class="service-label">Service Detected:</span>
                <span class="service-value">${serviceType.toUpperCase()} service is running</span>
            </div>
            <div class="service-detail-row">
                <span class="service-label">Port Status:</span>
                <span class="service-value">✅ Open and Accessible</span>
            </div>
        `;
    }

    return html;
}


function formatSNMPProtocolAnalysis(protocolInfo) {
    if (!protocolInfo || typeof protocolInfo !== 'object') {
        return '<p>No SNMP protocol information available</p>';
    }

    let html = '<div class="snmp-protocol-container">';

    // Connection Status
    if (protocolInfo.connection_test_successful !== undefined) {
        html += `
            <div class="snmp-section">
                <h5>📡 SNMP Connection Status</h5>
                <div class="snmp-status-item ${protocolInfo.connection_test_successful ? 'good' : 'critical'}">
                    <div class="snmp-status-label">UDP Connection</div>
                    <div class="snmp-status-value">${protocolInfo.connection_test_successful ? '✅ Successful' : '❌ Failed'}</div>
                </div>
            </div>
        `;
    }

    // SNMP Version
    if (protocolInfo.snmp_version) {
        html += `
            <div class="snmp-section">
                <h5>📋 SNMP Version</h5>
                <div class="snmp-status-item">
                    <div class="snmp-status-value">${safeDisplayValue(protocolInfo.snmp_version)}</div>
                </div>
            </div>
        `;
    }

    // Community Strings (if discovered)
    if (protocolInfo.community_strings && protocolInfo.community_strings.length > 0) {
        html += `
            <div class="snmp-section">
                <h5>🔑 Community Strings</h5>
                <div class="community-strings-list">
                    ${protocolInfo.community_strings.map(community => `
                        <span class="community-badge">${safeDisplayValue(community)}</span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function addEnhancedSSHAuditDisplay(scanData) {
    console.log('🔍 SSH Debug - addEnhancedSSHAuditDisplay called with:', scanData);

    if (scanData.service_type !== 'ssh') {
        console.log('🔍 SSH Debug - Not SSH service, skipping');
        return '';
    }

    if (!scanData.ssh_audit_data) {
        console.log('🔍 SSH Debug - No ssh_audit_data found');
        return '';
    }

    console.log('🔍 SSH Debug - ssh_audit_data:', scanData.ssh_audit_data);

    if (scanData.ssh_audit_data.error) {
        console.log('🔍 SSH Debug - SSH audit error:', scanData.ssh_audit_data.error);
        return renderSSHAuditError(scanData.ssh_audit_data.error);
    }

    // Get the formatted display or raw output
    let displayOutput = scanData.ssh_audit_data.formatted_for_display ||
                       scanData.ssh_audit_data.raw_output ||
                       'No SSH audit output available';

    console.log('🔍 SSH Debug - Display output found:', !!displayOutput);
    console.log('🔍 SSH Debug - Display output length:', displayOutput ? displayOutput.length : 0);

    if (displayOutput && displayOutput.length > 0) {
        // Get additional data for enhanced display
        const algorithms = scanData.ssh_audit_data.algorithms || {};
        const vulnerabilities = scanData.ssh_audit_data.vulnerabilities || [];
        const recommendations = scanData.ssh_audit_data.recommendations || [];
        const securityScore = scanData.ssh_audit_data.security_score;

        console.log('🔍 SSH Debug - Additional data:', {
            algorithms: Object.keys(algorithms).length,
            vulnerabilities: vulnerabilities.length,
            recommendations: recommendations.length,
            securityScore
        });

        const sshAuditHTML = `
            <div class="result-card ssh-audit-results-card">
                <h4>🔐 SSH Security Assessment (ssh-audit)</h4>
                <div class="ssh-audit-info">
                    <div class="audit-command">
                        <strong>🔧 Tool Used:</strong> 
                        <code>${scanData.ssh_audit_data.command_used || 'ssh-audit ' + scanData.ip + ':' + scanData.port}</code>
                    </div>
                    ${scanData.ssh_audit_data.tool_used ? `
                        <div class="audit-method">
                            <strong>📡 Method:</strong> ${scanData.ssh_audit_data.tool_used.replace(/_/g, ' ').toUpperCase()}
                        </div>
                    ` : ''}
                </div>
                
                <!-- Enhanced SSH Analysis Results -->
                <div class="ssh-analysis-container">
                    ${renderEnhancedSSHAnalysisFixed(scanData.ssh_audit_data)}
                </div>
                
                
                
                <!-- Formatted Output Display -->
                <div class="ssh-audit-formatted-output">
                    <h5>📋 Detailed Security Analysis</h5>
                    <div class="ssh-audit-content">
                        <pre class="ssh-audit-display">${Utils.escapeHtml(displayOutput)}</pre>
                    </div>
                </div>
                
                <!-- Raw Output (Collapsible) -->
                <details class="ssh-audit-raw-output">
                    <summary>
                        <span class="summary-icon">🔍</span>
                        <span class="summary-text">View Raw SSH-Audit Output</span>
                    </summary>
                    <div class="ssh-raw-container">
                        <pre class="ssh-raw-output">${Utils.escapeHtml(scanData.ssh_audit_data.raw_output || 'No raw output available')}</pre>
                    </div>
                </details>
            </div>
        `;

        console.log('✅ SSH Debug - SSH audit display created successfully');
        return sshAuditHTML;
    } else {
        // Fallback if no output
        console.log('🔍 SSH Debug - No display output, creating basic display');

        const sshAuditHTML = `
            <div class="result-card ssh-audit-basic-card">
                <h4>🔐 SSH Security Assessment</h4>
                <div class="ssh-audit-basic">
                    <div class="ssh-audit-status">
                        <p><strong>SSH-audit Status:</strong> Scan completed</p>
                        ${scanData.ssh_audit_data.command_used ? `
                            <p><strong>Command:</strong> <code>${scanData.ssh_audit_data.command_used}</code></p>
                        ` : ''}
                        ${scanData.ssh_audit_data.tool_used ? `
                            <p><strong>Method:</strong> ${scanData.ssh_audit_data.tool_used.replace(/_/g, ' ').toUpperCase()}</p>
                        ` : ''}
                    </div>
                    
                    <div class="ssh-basic-info">
                        <p>SSH security assessment was performed but detailed output formatting is not available.</p>
                        ${scanData.ssh_audit_data.scripts ? `
                            <p><strong>Analysis completed:</strong> SSH algorithms and configuration reviewed</p>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;

        return sshAuditHTML;
    }
}

function renderEnhancedSSHAnalysisFixed(sshAuditData) {
    console.log('🔍 SSH Debug - Rendering enhanced SSH analysis');

    let html = '<div class="ssh-enhanced-analysis">';

    // Server Information Section
    const serviceInfo = sshAuditData.service_info || {};
    if (Object.keys(serviceInfo).length > 0) {
        html += renderSSHServerInfoFixed(serviceInfo);
    }

    // Algorithm Analysis Section
    const algorithms = sshAuditData.algorithms || {};
    if (Object.keys(algorithms).length > 0) {
        html += renderSSHAlgorithmAnalysisFixed(algorithms);
    }

    // Vulnerabilities Section
    const vulnerabilities = sshAuditData.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
        html += renderSSHVulnerabilitiesFixed(vulnerabilities);
    }

    // Recommendations Section
    const recommendations = sshAuditData.recommendations || [];
    if (recommendations.length > 0) {
        html += renderSSHRecommendationsFixed(recommendations);
    }

    // Scripts Summary (if available)
    const scripts = sshAuditData.scripts || {};
    if (Object.keys(scripts).length > 0) {
        html += renderSSHScriptsSummary(scripts);
    }

    html += '</div>';
    return html;
}

function renderSSHScriptsSummary(scripts) {
    return `
        <div class="ssh-section scripts-summary">
            <h5>🔧 Analysis Summary</h5>
            <div class="scripts-list">
                ${Object.entries(scripts).map(([scriptName, result]) => `
                    <div class="script-item">
                        <strong>${scriptName.replace(/-/g, ' ').replace(/_/g, ' ').toUpperCase()}:</strong>
                        ${safeDisplayValue(result)}
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function renderSSHServerInfoFixed(serviceInfo) {
    return `
        <div class="ssh-section server-info">
            <h5>🖥️ SSH Server Information</h5>
            <div class="server-info-grid">
                ${serviceInfo.banner ? `
                    <div class="info-item">
                        <span class="info-label">Server Banner:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.banner)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.software ? `
                    <div class="info-item">
                        <span class="info-label">Software:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.software)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.server_type ? `
                    <div class="info-item">
                        <span class="info-label">Server Type:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.server_type)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.version ? `
                    <div class="info-item">
                        <span class="info-label">Version:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.version)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.protocol_version ? `
                    <div class="info-item">
                        <span class="info-label">Protocol:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.protocol_version)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.compatibility ? `
                    <div class="info-item">
                        <span class="info-label">Compatibility:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.compatibility)}</span>
                    </div>
                ` : ''}
                ${serviceInfo.compression ? `
                    <div class="info-item">
                        <span class="info-label">Compression:</span>
                        <span class="info-value">${safeDisplayValue(serviceInfo.compression)}</span>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function renderSSHAlgorithmAnalysisFixed(algorithms) {
    console.log('🔍 SSH Debug - Rendering algorithm analysis:', algorithms);

    let html = `
        <div class="ssh-section algorithm-analysis">
            <h5>🔐 Cryptographic Algorithm Analysis</h5>
    `;

    // Algorithm categories
    const sections = [
        { key: 'kex', title: 'Key Exchange', icon: '🔑' },
        { key: 'host_key', title: 'Host Key', icon: '🏠' },
        { key: 'encryption', title: 'Encryption', icon: '🔒' },
        { key: 'mac', title: 'MAC', icon: '✅' }
    ];

    let totalAlgorithms = 0;
    let secureCount = 0;
    let warningCount = 0;
    let criticalCount = 0;

    // Count algorithms by status
    for (const section of sections) {
        const algs = algorithms[section.key] || [];
        totalAlgorithms += algs.length;

        for (const alg of algs) {
            const status = alg.status || 'info';
            if (status === 'fail') {
                criticalCount++;
            } else if (status === 'warn') {
                warningCount++;
            } else {
                secureCount++;
            }
        }
    }

    // Add summary stats
    if (totalAlgorithms > 0) {
        html += `
            <div class="algorithm-summary">
                <div class="summary-stats">
                    <div class="stat-item total">
                        <span class="stat-number">${totalAlgorithms}</span>
                        <span class="stat-label">Total Algorithms</span>
                    </div>
                    <div class="stat-item secure">
                        <span class="stat-number">${secureCount}</span>
                        <span class="stat-label">Secure</span>
                    </div>
                    <div class="stat-item warning">
                        <span class="stat-number">${warningCount}</span>
                        <span class="stat-label">Warnings</span>
                    </div>
                    <div class="stat-item critical">
                        <span class="stat-number">${criticalCount}</span>
                        <span class="stat-label">Critical</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Render each algorithm category
    for (const section of sections) {
        const algs = algorithms[section.key] || [];
        if (algs.length === 0) continue;

        html += `
            <div class="algorithm-category">
                <h6>${section.icon} ${section.title} Algorithms (${algs.length})</h6>
                <div class="algorithm-list">
        `;

        // Show critical issues first, then warnings, then secure ones
        const failed = algs.filter(a => a.status === 'fail');
        const warned = algs.filter(a => a.status === 'warn');
        const secure = algs.filter(a => !a.status || a.status === 'info').slice(0, 3);

        console.log(`🔍 SSH Debug - ${section.title}: ${failed.length} failed, ${warned.length} warned, ${secure.length} secure`);

        [...failed, ...warned, ...secure].forEach(alg => {
            const status = alg.status || 'info';
            const statusText = status === 'fail' ? '❌ CRITICAL' :
                              status === 'warn' ? '⚠️ WARNING' : '✅ SECURE';
            const statusClass = status === 'fail' ? 'critical' :
                               status === 'warn' ? 'warning' : 'secure';

            html += `
                <div class="algorithm-item ${status}">
                    <div class="algorithm-header">
                        <span class="algorithm-name">${safeDisplayValue(alg.algorithm)}</span>
                        <span class="algorithm-status ${statusClass}">${statusText}</span>
                    </div>
                    ${alg.description ? `
                        <div class="algorithm-description">${safeDisplayValue(alg.description)}</div>
                    ` : ''}
                </div>
            `;
        });

        if (algs.length > failed.length + warned.length + 3) {
            html += `<div class="algorithm-more">... and ${algs.length - failed.length - warned.length - 3} more secure algorithms</div>`;
        }

        html += '</div></div>';
    }

    html += '</div>';
    return html;
}

function renderSSHVulnerabilitiesFixed(vulnerabilities) {
    return `
        <div class="ssh-section security-issues">
            <h5>🛡️ Security Issues Found (${vulnerabilities.length})</h5>
            <div class="issues-list">
                ${vulnerabilities.map(vuln => `
                    <div class="issue-item ${(vuln.severity || 'medium').toLowerCase()}">
                        <div class="issue-header">
                            <span class="issue-title">${safeDisplayValue(vuln.title || vuln.id)}</span>
                            <span class="issue-severity ${(vuln.severity || 'medium').toLowerCase()}">${vuln.severity || 'Medium'}</span>
                        </div>
                        <div class="issue-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                        ${vuln.recommendation ? `
                            <div class="issue-recommendation">
                                <strong>💡 Fix:</strong> ${safeDisplayValue(vuln.recommendation)}
                            </div>
                        ` : ''}
                        ${vuln.algorithm_name ? `
                            <div class="issue-metadata">
                                <strong>Algorithm:</strong> <code>${safeDisplayValue(vuln.algorithm_name)}</code>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function renderSSHRecommendationsFixed(recommendations) {
    return `
        <div class="ssh-section recommendations">
            <h5>💡 Security Recommendations</h5>
            <div class="recommendations-list">
                ${recommendations.slice(0, 10).map((rec, index) => `
                    <div class="recommendation-item">
                        <span class="rec-number">${index + 1}</span>
                        <span class="rec-text">${safeDisplayValue(rec)}</span>
                    </div>
                `).join('')}
                ${recommendations.length > 10 ? `
                    <div class="recommendation-item more-recs">
                        <span class="rec-number">+</span>
                        <span class="rec-text">And ${recommendations.length - 10} more recommendations...</span>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function parseEnhancedSSHAuditOutput(output) {
    console.log('🔍 SSH Debug - Parsing enhanced SSH audit output...');

    const parsed = {
        general: {},
        algorithms: {
            kex: [],
            hostKey: [],
            encryption: [],
            mac: []
        },
        vulnerabilities: [],
        recommendations: [],
        summary: {},
        algorithmAnalysis: {
            totalAlgorithms: 0,
            weakAlgorithms: 0,
            deprecatedAlgorithms: 0,
            secureAlgorithms: 0
        }
    };

    if (!output || typeof output !== 'string') {
        return parsed;
    }

    try {
        // Try to parse as JSON first
        if (output.trim().startsWith('{')) {
            const jsonData = JSON.parse(output);
            return parseSSHAuditFromJSON(jsonData);
        }
    } catch (e) {
        console.log('🔍 SSH Debug - Not JSON format, parsing as text');
    }

    // Parse text format
    const lines = output.split('\n');
    let currentSection = null;
    let algorithmCount = 0;

    for (const line of lines) {
        const trimmed = line.trim();

        // Parse general information
        if (trimmed.startsWith('(gen) banner:')) {
            parsed.general.banner = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) software:')) {
            parsed.general.software = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) compatibility:')) {
            parsed.general.compatibility = trimmed.split(':', 2)[1]?.trim() || '';
        } else if (trimmed.startsWith('(gen) compression:')) {
            parsed.general.compression = trimmed.split(':', 2)[1]?.trim() || '';
        }

        // Detect algorithm sections
        else if (trimmed.includes('key exchange algorithms')) {
            currentSection = 'kex';
        } else if (trimmed.includes('host-key algorithms')) {
            currentSection = 'hostKey';
        } else if (trimmed.includes('encryption algorithms')) {
            currentSection = 'encryption';
        } else if (trimmed.includes('message authentication code')) {
            currentSection = 'mac';
        } else if (trimmed.includes('algorithm recommendations')) {
            currentSection = 'recommendations';
        } else if (trimmed.startsWith('#')) {
            currentSection = null;
        }

        // Parse algorithm lines with enhanced analysis
        else if (currentSection && trimmed.startsWith('(')) {
            if (currentSection !== 'recommendations') {
                const algorithm = parseEnhancedAlgorithmLine(trimmed);
                if (algorithm) {
                    parsed.algorithms[currentSection].push(algorithm);
                    algorithmCount++;

                    // Enhanced algorithm analysis
                    if (algorithm.status === 'fail') {
                        parsed.algorithmAnalysis.weakAlgorithms++;
                        parsed.vulnerabilities.push(createVulnerabilityFromAlgorithm(algorithm, currentSection));
                    } else if (algorithm.status === 'warn') {
                        parsed.algorithmAnalysis.deprecatedAlgorithms++;
                    } else {
                        parsed.algorithmAnalysis.secureAlgorithms++;
                    }
                }
            } else if (trimmed.startsWith('(rec)')) {
                const rec = trimmed.substring(5).trim();
                if (rec) {
                    parsed.recommendations.push(rec);
                }
            }
        }
    }

    parsed.algorithmAnalysis.totalAlgorithms = algorithmCount;

    // Generate enhanced summary
    parsed.summary = generateEnhancedSecuritySummary(parsed);

    console.log('🔍 SSH Debug - Enhanced parsing complete:', parsed);
    return parsed;
}


function parseSSHAuditFromJSON(jsonData) {
    console.log('🔍 SSH Debug - Parsing JSON format SSH audit data');

    const parsed = {
        general: {},
        algorithms: {
            kex: [],
            hostKey: [],
            encryption: [],
            mac: []
        },
        vulnerabilities: [],
        recommendations: [],
        summary: {},
        algorithmAnalysis: {
            totalAlgorithms: 0,
            weakAlgorithms: 0,
            deprecatedAlgorithms: 0,
            secureAlgorithms: 0
        }
    };

    // Parse banner information
    if (jsonData.banner) {
        parsed.general.banner = jsonData.banner.raw || jsonData.banner.software || '';
        parsed.general.software = jsonData.banner.software || '';
        parsed.general.protocol = jsonData.banner.protocol || '';
    }

    // Parse algorithms with enhanced analysis
    if (jsonData.algorithms) {
        const algMapping = {
            'kex': 'kex',
            'key': 'hostKey',
            'enc': 'encryption',
            'mac': 'mac'
        };

        Object.entries(algMapping).forEach(([jsonKey, parsedKey]) => {
            if (jsonData.algorithms[jsonKey] && Array.isArray(jsonData.algorithms[jsonKey])) {
                jsonData.algorithms[jsonKey].forEach(alg => {
                    const algorithm = {
                        name: alg,
                        status: 'info', // Default, will be updated based on recommendations
                        description: `${alg} algorithm`,
                        severity: 'Info'
                    };

                    parsed.algorithms[parsedKey].push(algorithm);
                    parsed.algorithmAnalysis.totalAlgorithms++;
                    parsed.algorithmAnalysis.secureAlgorithms++; // Default to secure, update based on recommendations
                });
            }
        });
    }

    // Parse recommendations and update algorithm status
    if (jsonData.algorithms && jsonData.algorithms.recommendations) {
        const recs = jsonData.algorithms.recommendations;

        // Process critical recommendations
        if (recs.critical && recs.critical.del) {
            recs.critical.del.forEach(alg => {
                updateAlgorithmStatus(parsed, alg, 'fail', 'Critical');
                parsed.algorithmAnalysis.weakAlgorithms++;
                parsed.algorithmAnalysis.secureAlgorithms--;
            });
        }

        // Process warning recommendations
        if (recs.warning && recs.warning.del) {
            recs.warning.del.forEach(alg => {
                updateAlgorithmStatus(parsed, alg, 'warn', 'Medium');
                parsed.algorithmAnalysis.deprecatedAlgorithms++;
                parsed.algorithmAnalysis.secureAlgorithms--;
            });
        }

        // Process informational recommendations
        if (recs.info && recs.info.del) {
            recs.info.del.forEach(alg => {
                updateAlgorithmStatus(parsed, alg, 'info', 'Low');
            });
        }
    }

    // Generate enhanced summary
    parsed.summary = generateEnhancedSecuritySummary(parsed);

    return parsed;
}


function updateAlgorithmStatus(parsed, algorithmName, status, severity) {
    Object.values(parsed.algorithms).forEach(algList => {
        algList.forEach(alg => {
            if (alg.name === algorithmName) {
                alg.status = status;
                alg.severity = severity;

                if (status === 'fail' || status === 'warn') {
                    // Create vulnerability for problematic algorithms
                    const vuln = createVulnerabilityFromAlgorithm(alg, getAlgorithmType(alg.name, parsed));
                    parsed.vulnerabilities.push(vuln);
                }
            }
        });
    });
}

function getAlgorithmType(algorithmName, parsed) {
    for (const [type, algorithms] of Object.entries(parsed.algorithms)) {
        if (algorithms.some(alg => alg.name === algorithmName)) {
            return type;
        }
    }
    return 'unknown';
}

function parseEnhancedAlgorithmLine(line) {
    try {
        // Match pattern: (type) algorithm-name -- [status] description
        const match = line.match(/\((\w+)\)\s+([^\s]+)\s+--\s+\[(\w+)\]\s+(.+)/);
        if (!match) return null;

        const [, type, name, status, description] = match;

        return {
            type,
            name: name.trim(),
            status: status.toLowerCase(),
            description: description.trim(),
            severity: getAlgorithmSeverity(status, description)
        };
    } catch (e) {
        console.warn('Failed to parse algorithm line:', line, e);
        return null;
    }
}

function generateEnhancedSecuritySummary(parsed) {
    const analysis = {
        totalAlgorithms: 0,
        weakAlgorithms: 0,
        deprecatedAlgorithms: 0,
        secureAlgorithms: 0
    };

    // Count algorithms by status
    Object.values(parsed.algorithms || {}).forEach(algList => {
        algList.forEach(alg => {
            analysis.totalAlgorithms++;
            if (alg.status === 'fail') {
                analysis.weakAlgorithms++;
            } else if (alg.status === 'warn') {
                analysis.deprecatedAlgorithms++;
            } else {
                analysis.secureAlgorithms++;
            }
        });
    });

    return {
        totalAlgorithms: analysis.totalAlgorithms,
        weakAlgorithms: analysis.weakAlgorithms,
        deprecatedAlgorithms: analysis.deprecatedAlgorithms,
        secureAlgorithms: analysis.secureAlgorithms,
        securityLevel: getSecurityLevel(analysis),
        majorIssues: analysis.weakAlgorithms,
        minorIssues: analysis.deprecatedAlgorithms,
        overallStatus: getOverallStatus(analysis)
    };
}

function renderEnhancedSSHAnalysis(parsedData) {
    let html = '<div class="ssh-enhanced-analysis">';

    // Server Information Section
    if (parsedData.general && Object.keys(parsedData.general).length > 0) {
        html += renderSSHServerInfo(parsedData.general);
    }

    // Algorithm Analysis Section (Enhanced)
    html += renderEnhancedAlgorithmAnalysis(parsedData.algorithms, parsedData.algorithmAnalysis);

    // Security Issues Section
    if (parsedData.vulnerabilities && parsedData.vulnerabilities.length > 0) {
        html += renderSSHSecurityIssues(parsedData.vulnerabilities);
    }

    // Recommendations Section
    if (parsedData.recommendations && parsedData.recommendations.length > 0) {
        html += renderSSHRecommendations(parsedData.recommendations);
    }

    // Overall Security Assessment (without score)
    html += renderSSHSecuritySummary(parsedData.summary);

    html += '</div>';
    return html;
}

function renderSSHServerInfo(general) {
    return `
        <div class="ssh-section server-info">
            <h5>🖥️ SSH Server Information</h5>
            <div class="server-info-grid">
                ${general.banner ? `
                    <div class="info-item">
                        <span class="info-label">Server Banner:</span>
                        <span class="info-value">${safeDisplayValue(general.banner)}</span>
                    </div>
                ` : ''}
                ${general.software ? `
                    <div class="info-item">
                        <span class="info-label">Software:</span>
                        <span class="info-value">${safeDisplayValue(general.software)}</span>
                    </div>
                ` : ''}
                ${general.protocol ? `
                    <div class="info-item">
                        <span class="info-label">Protocol:</span>
                        <span class="info-value">${safeDisplayValue(general.protocol)}</span>
                    </div>
                ` : ''}
                ${general.compatibility ? `
                    <div class="info-item">
                        <span class="info-label">Compatibility:</span>
                        <span class="info-value">${safeDisplayValue(general.compatibility)}</span>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}


function renderEnhancedAlgorithmAnalysis(algorithms, analysis) {
    console.log('🔍 SSH Debug - Rendering algorithms:', algorithms);
    console.log('🔍 SSH Debug - Analysis data:', analysis);

    let html = `
        <div class="ssh-section algorithm-analysis">
            <h5>🔐 Cryptographic Algorithm Analysis</h5>
            
            <div class="algorithm-summary">
                <div class="summary-stats">
                    <div class="stat-item total">
                        <span class="stat-number">${analysis.totalAlgorithms || 0}</span>
                        <span class="stat-label">Total Algorithms</span>
                    </div>
                    <div class="stat-item secure">
                        <span class="stat-number">${analysis.secureAlgorithms || 0}</span>
                        <span class="stat-label">Secure</span>
                    </div>
                    <div class="stat-item deprecated">
                        <span class="stat-number">${analysis.deprecatedAlgorithms || 0}</span>
                        <span class="stat-label">Deprecated</span>
                    </div>
                    <div class="stat-item weak">
                        <span class="stat-number">${analysis.weakAlgorithms || 0}</span>
                        <span class="stat-label">Weak/Broken</span>
                    </div>
                </div>
            </div>
    `;

    // Algorithm categories
    const sections = [
        { key: 'kex', title: 'Key Exchange', icon: '🔑' },
        { key: 'host_key', title: 'Host Key', icon: '🏠' },
        { key: 'encryption', title: 'Encryption', icon: '🔒' },
        { key: 'mac', title: 'MAC', icon: '✅' }
    ];

    for (const section of sections) {
        const algs = algorithms[section.key] || [];
        if (algs.length === 0) continue;

        html += `
            <div class="algorithm-category">
                <h6>${section.icon} ${section.title} Algorithms (${algs.length})</h6>
                <div class="algorithm-list">
        `;

        // Show critical issues first, then warnings, then secure ones
        const failed = algs.filter(a => a.status === 'fail');
        const warned = algs.filter(a => a.status === 'warn');
        const secure = algs.filter(a => a.status === 'info').slice(0, 3);

        console.log(`🔍 SSH Debug - ${section.title}: ${failed.length} failed, ${warned.length} warned, ${secure.length} secure`);

        [...failed, ...warned, ...secure].forEach(alg => {
            const statusText = alg.status === 'fail' ? '❌ CRITICAL' :
                              alg.status === 'warn' ? '⚠️ WARNING' : '✅ SECURE';
            const statusClass = alg.status === 'fail' ? 'critical' :
                               alg.status === 'warn' ? 'warning' : 'secure';

            html += `
                <div class="algorithm-item ${alg.status}">
                    <div class="algorithm-header">
                        <span class="algorithm-name">${safeDisplayValue(alg.algorithm)}</span>
                        <span class="algorithm-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="algorithm-description">${safeDisplayValue(alg.description)}</div>
                </div>
            `;
        });

        if (algs.length > failed.length + warned.length + 3) {
            html += `<div class="algorithm-more">... and ${algs.length - failed.length - warned.length - 3} more secure algorithms</div>`;
        }

        html += '</div></div>';
    }

    html += '</div>';
    return html;
}

function renderSSHSecurityIssues(vulnerabilities) {
    return `
        <div class="ssh-section security-issues">
            <h5>🛡️ Security Issues Found (${vulnerabilities.length})</h5>
            <div class="issues-list">
                ${vulnerabilities.map(vuln => `
                    <div class="issue-item ${vuln.severity.toLowerCase()}">
                        <div class="issue-header">
                            <span class="issue-title">${safeDisplayValue(vuln.title)}</span>
                            <span class="issue-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        </div>
                        <div class="issue-description">${safeDisplayValue(vuln.description)}</div>
                        ${vuln.recommendation ? `
                            <div class="issue-recommendation">
                                <strong>💡 Fix:</strong> ${safeDisplayValue(vuln.recommendation)}
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function renderSSHRecommendations(recommendations) {
    return `
        <div class="ssh-section recommendations">
            <h5>💡 Security Recommendations</h5>
            <div class="recommendations-list">
                ${recommendations.map((rec, index) => `
                    <div class="recommendation-item">
                        <span class="rec-number">${index + 1}</span>
                        <span class="rec-text">${safeDisplayValue(rec)}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}


function renderSSHSecuritySummary(summary) {
    if (!summary || Object.keys(summary).length === 0) return '';

    const statusClass = summary.overallStatus || 'unknown';
    const statusText = {
        'secure': '✅ Secure Configuration',
        'warning': '⚠️ Some Issues Found',
        'critical': '❌ Critical Issues Present',
        'unknown': 'ℹ️ Analysis Complete'
    };

    return `
        <div class="ssh-section security-summary">
            <h5>📊 Security Assessment Summary</h5>
            <div class="summary-content">
                <div class="overall-status ${statusClass}">
                    <div class="status-indicator">
                        ${statusText[statusClass] || statusText.unknown}
                    </div>
                    <div class="status-description">
                        ${summary.securityLevel ? `Security Level: ${summary.securityLevel}` : 'SSH security assessment completed'}
                    </div>
                </div>
                
                ${summary.majorIssues > 0 || summary.minorIssues > 0 ? `
                    <div class="issues-summary">
                        ${summary.majorIssues > 0 ? `
                            <div class="issue-count critical">
                                <span class="count">${summary.majorIssues}</span>
                                <span class="label">Critical Issues</span>
                            </div>
                        ` : ''}
                        ${summary.minorIssues > 0 ? `
                            <div class="issue-count warning">
                                <span class="count">${summary.minorIssues}</span>
                                <span class="label">Minor Issues</span>
                            </div>
                        ` : ''}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}


function renderSSHAnalysisCard(scanData) {
    if (scanData.service_type !== 'ssh') return '';

    return `
        <div class="result-card ssh-analysis">
            <h4>🔐 SSH Security Analysis</h4>
            <div class="ssh-analysis-content">
                ${formatSSHServiceInfo(scanData.service_info || {}, 'ssh')}
            </div>
        </div>
    `;
}

function showDeepSMTPScanButton(scanData) {
    // Check if nmap is available for deep scanning
    const nmapAvailable = scanData.nmap_enhanced || scanData.scanner_capabilities?.nmap_available;

    if (!nmapAvailable) {
        console.log('Deep SMTP scan not available - nmap not detected');
        return;
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-smtp-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep SMTP Scan (All Scripts)</span>
    `;
    deepScanBtn.id = 'deepSMTPScanBtn';
    deepScanBtn.onclick = () => startDeepSMTPScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        const existingBtn = document.getElementById('deepSMTPScanBtn');
        if (existingBtn) {
            existingBtn.remove();
        }

        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep SMTP Scan button added');
    }
}

async function startDeepSMTPScan(previousScanData) {
    console.log('🎯 Starting deep SMTP scan for:', previousScanData);

    // Show warning dialog - EXTRA WARNING for SMTP due to password attacks
    const userConfirmed = confirm(DEEP_SCAN_WARNINGS.smtp.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep SMTP scan');
        Utils.showNotification('Deep SMTP scan cancelled by user', 'info');
        return;
    }

    // Secondary confirmation for SMTP password attacks
    const passwordAttackConfirmed = confirm(
        `⚠️ FINAL CONFIRMATION ⚠️\n\n` +
        `This SMTP deep scan includes PASSWORD ATTACKS against discovered user accounts.\n\n` +
        `🔓 PASSWORD ATTACK DETAILS:\n` +
        `• Will attempt common passwords against mail accounts\n` +
        `• May try 20-30 passwords per discovered user\n` +
        `• Could trigger account lockouts or IP blocking\n` +
        `• All attempts will be logged by the mail server\n\n` +
        `Are you ABSOLUTELY SURE you want to proceed with password attacks?\n` +
        `(This could be considered intrusive testing)`
    );

    if (!passwordAttackConfirmed) {
        console.log('🚫 User cancelled SMTP password attacks');
        Utils.showNotification('SMTP password attacks cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep SMTP scan with password attacks - proceeding...');

    const deepBtn = document.getElementById('deepSMTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All SMTP Scripts + Password Attacks...</span>
        `;
    }

    try {
        showDeepSMTPScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'smtp',
            skipDnsAnalysis: true
        };

        console.log('🚀 Starting deep SMTP scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep SMTP scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep SMTP scan results:', deepResults);

        showDeepSMTPResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep SMTP scan error:', error);
        Utils.showNotification(`Deep SMTP scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep SMTP Scan (All Scripts)</span>
            `;
        }
    }
}

function showDeepSMTPScanProgress(scanData) {

    if (!aggressiveScanAvailable) {
        console.log('Deep SMTP scan not available - aggressive scanning not supported');
        return;
    }

    const nmapAvailable = scanData.nmap_enhanced || scanData.scanner_capabilities?.nmap_available;

    if (!nmapAvailable) {
        console.log('Deep SMTP scan not available - nmap not detected');
        return;
    }

    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'SMTP (Deep Scan - All Scripts + DNS Analysis)';
    }

    updateScanProgress(25, 'Loading comprehensive SMTP NSE script suite...');

    setTimeout(() => updateScanProgress(50, 'Running smtp-* scripts and DNS analysis...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep SMTP and DNS findings...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep SMTP scan completed'), 3000);
}

// Replace the showDeepSMTPResults function in active-scan.js

function showDeepSMTPResults(deepResults, originalResults) {
    console.log('🔍 Showing deep SMTP scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep SMTP Scan Results (Enhanced Enumeration + Password Attacks)
            <span class="deep-scan-badge">Complete</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show password attack results FIRST (most important)
    if (deepResults.advanced_findings && deepResults.advanced_findings.password_attacks) {
        const attacks = deepResults.advanced_findings.password_attacks;
        console.log('🔍 Password attacks data:', attacks);

        if (attacks.successful_credentials && attacks.successful_credentials.length > 0) {
            const credentialsCard = document.createElement('div');
            credentialsCard.className = 'result-card credentials-found-card critical-finding';
            credentialsCard.innerHTML = `
                <h4>🔓 SMTP Credentials Discovered</h4>
                <div class="credentials-alert">
                    <div class="alert-icon">🚨</div>
                    <div class="alert-text">
                        <strong>CRITICAL SECURITY ISSUE:</strong> Valid SMTP credentials found!
                    </div>
                </div>
                <div class="credentials-list">
                    ${attacks.successful_credentials.map(cred => `
                        <div class="credential-item critical">
                            <div class="credential-header">
                                <span class="credential-type">📧 SMTP Account</span>
                                <span class="credential-status">✅ Verified</span>
                            </div>
                            <div class="credential-info">
                                <div class="credential-field">
                                    <strong>Username:</strong> 
                                    <code class="credential-value">${safeDisplayValue(cred.username)}</code>
                                </div>
                                <div class="credential-field">
                                    <strong>Password:</strong> 
                                    <code class="credential-value">${safeDisplayValue(cred.password)}</code>
                                </div>
                            </div>
                            <div class="credential-impact">
                                <span class="impact-item">📤 Can send emails</span>
                                <span class="impact-item">📥 Can access mailbox</span>
                                <span class="impact-item">⚠️ Potential data access</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;

            resultsContent.appendChild(credentialsCard);
        } else if (attacks.total_users_attacked > 0) {
            // Show attack attempt summary even if no credentials found
            const attackSummaryCard = document.createElement('div');
            attackSummaryCard.className = 'result-card attack-summary-card';
            attackSummaryCard.innerHTML = `
                <h4>💥 Password Attack Summary</h4>
                <div class="attack-summary-grid">
                    <div class="summary-stat">
                        <div class="stat-number">${attacks.total_users_attacked}</div>
                        <div class="stat-label">Users Attacked</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">${Math.round(attacks.total_duration || 0)}s</div>
                        <div class="stat-label">Duration</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">0</div>
                        <div class="stat-label">Credentials Found</div>
                    </div>
                </div>
                <div class="attack-details">
                    <p><strong>Result:</strong> No credentials found with common passwords</p>
                    <p><em>💡 Consider using custom wordlists specific to this organization</em></p>
                </div>
            `;
            resultsContent.appendChild(attackSummaryCard);
        }

        // Show individual attack results
        if (attacks.individual_attacks && Object.keys(attacks.individual_attacks).length > 0) {
            const individualCard = document.createElement('div');
            individualCard.className = 'result-card individual-attacks-card';
            individualCard.innerHTML = `
                <h4>🎯 Individual Attack Results</h4>
                <div class="individual-attacks-list">
                    ${Object.entries(attacks.individual_attacks).map(([username, result]) => `
                        <div class="attack-result-item ${result.success ? 'success' : 'failed'}">
                            <div class="attack-username">
                                <strong>👤 ${safeDisplayValue(username)}</strong>
                            </div>
                            <div class="attack-result">
                                ${result.success ? 
                                    `<span class="result-success">✅ Password: ${safeDisplayValue(result.password_found)}</span>` :
                                    `<span class="result-failed">❌ No password found</span>`
                                }
                            </div>
                            <div class="attack-stats">
                                <span>⏱️ ${result.attack_duration || 0}s</span>
                                <span>🔐 ${result.passwords_tested || 0} passwords tested</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
            resultsContent.appendChild(individualCard);
        }
    }

    // Show enumeration results
    if (deepResults.advanced_findings && deepResults.advanced_findings.users_discovered &&
        deepResults.advanced_findings.users_discovered.length > 0) {

        const enumerationCard = document.createElement('div');
        enumerationCard.className = 'result-card enumeration-results-card';
        enumerationCard.innerHTML = `
            <h4>👥 User Enumeration Results</h4>
            <div class="enumeration-summary">
                <p><strong>Discovery Method:</strong> ${deepResults.advanced_findings.methods_used?.join(', ') || 'VRFY/EXPN Commands'}</p>
                <p><strong>Users Found:</strong> ${deepResults.advanced_findings.users_discovered.length}</p>
            </div>
            <div class="discovered-users">
                ${deepResults.advanced_findings.users_discovered.map(user => `
                    <span class="discovered-user">${safeDisplayValue(user)}</span>
                `).join('')}
            </div>
        `;
        resultsContent.appendChild(enumerationCard);
    }

    // Show raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep SMTP Scan Output</h4>
            <div class="nmap-command-info">
                <strong>Command:</strong> ${deepResults.nmap_data.command_used || 'nmap with all smtp-* scripts'}
            </div>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;

        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepSMTPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    // Determine notification message
    const attackSummary = deepResults.advanced_findings?.attack_summary;
    const credentialsFound = attackSummary?.credentials_found || 0;

    if (credentialsFound > 0) {
        Utils.showNotification(`🚨 CRITICAL: ${credentialsFound} SMTP credentials discovered!`, 'error');
    } else {
        Utils.showNotification('Deep SMTP scan with password attacks completed', 'success');
    }

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

// Format SMTP DNS Analysis for Display
function formatSMTPDNSAnalysis(dnsAnalysis) {
    let html = '<div class="smtp-dns-container">';

    // Domain extracted
    if (dnsAnalysis.domain_extracted) {
        html += `
            <div class="dns-section">
                <h5>📧 Analyzed Domain</h5>
                <div class="dns-record-item">
                    <div class="dns-record-type">Domain</div>
                    <div class="dns-record-value">${safeDisplayValue(dnsAnalysis.domain_extracted)}</div>
                </div>
            </div>
        `;
    }

    // DNS Security Status Overview
    html += '<div class="dns-section"><h5>🔒 DNS Security Status</h5>';
    html += '<div class="dns-security-status">';

    // SPF Status
    const spfStatus = dnsAnalysis.spf_record ?
        (dnsAnalysis.spf_analysis?.security_level === 'critical' ? 'critical' :
         dnsAnalysis.spf_analysis?.security_level === 'warning' ? 'warning' : 'good') : 'warning';
    html += `
        <div class="dns-status-item ${spfStatus}">
            <div class="dns-status-label">SPF</div>
            <div class="dns-status-value">${dnsAnalysis.spf_record ? '✓' : '✗'}</div>
        </div>
    `;

    // DMARC Status
    const dmarcStatus = dnsAnalysis.dmarc_record ?
        (dnsAnalysis.dmarc_analysis?.security_level === 'warning' ? 'warning' : 'good') : 'warning';
    html += `
        <div class="dns-status-item ${dmarcStatus}">
            <div class="dns-status-label">DMARC</div>
            <div class="dns-status-value">${dnsAnalysis.dmarc_record ? '✓' : '✗'}</div>
        </div>
    `;

    // DKIM Status
    const dkimCount = Object.keys(dnsAnalysis.dkim_records || {}).length;
    const dkimStatus = dkimCount > 0 ? 'good' : 'warning';
    html += `
        <div class="dns-status-item ${dkimStatus}">
            <div class="dns-status-label">DKIM</div>
            <div class="dns-status-value">${dkimCount} keys</div>
        </div>
    `;

    html += '</div></div>';

    // SPF Record Details
    if (dnsAnalysis.spf_record) {
        html += `
            <div class="dns-section">
                <h5>📝 SPF Record Analysis</h5>
                <div class="dns-record-item">
                    <div class="dns-record-type">SPF Record</div>
                    <div class="dns-record-value">${safeDisplayValue(dnsAnalysis.spf_record)}</div>
                </div>
        `;

        if (dnsAnalysis.spf_analysis) {
            const analysis = dnsAnalysis.spf_analysis;
            html += `
                <div class="spf-analysis-details">
                    <p><strong>Security Level:</strong> ${analysis.security_level || 'Unknown'}</p>
                    <p><strong>All Mechanism:</strong> ${analysis.all_mechanism || 'Not specified'}</p>
                    <p><strong>Include Count:</strong> ${analysis.include_count || 0}</p>
                    ${analysis.issues && analysis.issues.length > 0 ? `
                        <div class="spf-issues">
                            <strong>Issues:</strong>
                            <ul>${analysis.issues.map(issue => `<li>${safeDisplayValue(issue)}</li>`).join('')}</ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        html += '</div>';
    }

    // DMARC Record Details
    if (dnsAnalysis.dmarc_record) {
        html += `
            <div class="dns-section">
                <h5>🛡️ DMARC Record Analysis</h5>
                <div class="dns-record-item">
                    <div class="dns-record-type">DMARC Record</div>
                    <div class="dns-record-value">${safeDisplayValue(dnsAnalysis.dmarc_record)}</div>
                </div>
        `;

        if (dnsAnalysis.dmarc_analysis) {
            const analysis = dnsAnalysis.dmarc_analysis;
            html += `
                <div class="dmarc-analysis-details">
                    <p><strong>Policy:</strong> ${analysis.policy || 'Unknown'}</p>
                    <p><strong>Percentage:</strong> ${analysis.percentage || 100}%</p>
                    ${analysis.subdomain_policy ? `<p><strong>Subdomain Policy:</strong> ${analysis.subdomain_policy}</p>` : ''}
                    ${analysis.issues && analysis.issues.length > 0 ? `
                        <div class="dmarc-issues">
                            <strong>Issues:</strong>
                            <ul>${analysis.issues.map(issue => `<li>${safeDisplayValue(issue)}</li>`).join('')}</ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        html += '</div>';
    }

    // DKIM Records
    if (dnsAnalysis.dkim_records && Object.keys(dnsAnalysis.dkim_records).length > 0) {
        html += `
            <div class="dns-section">
                <h5>🔑 DKIM Records Found</h5>
        `;

        Object.entries(dnsAnalysis.dkim_records).forEach(([selector, record]) => {
            html += `
                <div class="dns-record-item">
                    <div class="dns-record-type">DKIM Selector: ${selector}</div>
                    <div class="dns-record-value">${safeDisplayValue(record).substring(0, 100)}${record.length > 100 ? '...' : ''}</div>
                </div>
            `;
        });

        html += '</div>';
    }

    // MX Records (if available)
    if (dnsAnalysis.mx_records && dnsAnalysis.mx_records.length > 0) {
        html += `
            <div class="dns-section">
                <h5>📮 MX Records</h5>
        `;

        dnsAnalysis.mx_records.forEach(mx => {
            html += `
                <div class="dns-record-item">
                    <div class="dns-record-type">MX Record</div>
                    <div class="dns-record-value">${safeDisplayValue(mx)}</div>
                </div>
            `;
        });

        html += '</div>';
    }

    // Method used
    if (dnsAnalysis.method_used) {
        html += `
            <div class="dns-section">
                <h5>🔧 Analysis Method</h5>
                <div class="dns-record-item">
                    <div class="dns-record-type">Method</div>
                    <div class="dns-record-value">${safeDisplayValue(dnsAnalysis.method_used)}</div>
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// Add SMTP-specific script highlighting
function addSMTPScriptHighlighting() {
    // Add CSS for SMTP script highlighting
    const style = document.createElement('style');
    style.textContent = `
        .script-result[data-script^="smtp-"] .script-name {
            color: #059669;
        }

        .script-result[data-script="smtp-open-relay"] {
            border-left: 3px solid #ef4444;
        }

        .script-result[data-script="smtp-enum-users"] {
            border-left: 3px solid #f59e0b;
        }

        .script-result[data-script="smtp-commands"] {
            border-left: 3px solid #3b82f6;
        }

        .script-result[data-script="smtp-ntlm-info"] {
            border-left: 3px solid #8b5cf6;
        }
    `;
    document.head.appendChild(style);
}

// SMTP Vulnerability Item Renderer
function renderSMTPVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'smtp_scanner';

    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap_nse') || vuln.detection_method?.includes('smtp-')) {
        badgeText = 'NMAP NSE';
        badgeClass = 'nmap-badge';
    } else if (source.includes('dns_analysis')) {
        badgeText = 'DNS ANALYSIS';
        badgeClass = 'dns-badge';
    } else if (source.includes('manual_verification')) {
        badgeText = 'MANUAL';
        badgeClass = 'manual-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} smtp-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'SMTP-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'SMTP Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}


function formatSMTPAdvancedFindings(findings) {
    let html = '<div class="smtp-advanced-findings-content">';

    // Connection Analysis
    if (findings.connection_analysis) {
        html += formatSMTPConnectionAnalysis(findings.connection_analysis);
    }

    // Command Testing Results
    if (findings.command_testing || findings.extensive_command_testing) {
        const commandData = findings.command_testing || findings.extensive_command_testing;
        html += formatSMTPCommandTesting(commandData);
    }

    // Relay Testing Results
    if (findings.relay_testing || findings.comprehensive_relay_testing) {
        const relayData = findings.relay_testing || findings.comprehensive_relay_testing;
        html += formatSMTPRelayTesting(relayData);
    }

    // User Enumeration Results
    if (findings.user_enumeration) {
        html += formatSMTPUserEnumeration(findings.user_enumeration);
    }

    // Timing Analysis Results
    if (findings.timing_analysis) {
        html += formatSMTPTimingAnalysis(findings.timing_analysis);
    }

    html += '</div>';
    return html;
}

function formatSMTPConnectionAnalysis(connectionAnalysis) {
    let html = `
        <div class="finding-section smtp-connection-section">
            <h5>🔌 Connection Analysis</h5>
    `;

    if (connectionAnalysis.response_times && connectionAnalysis.response_times.length > 0) {
        const avgTime = connectionAnalysis.average_response_time ||
            (connectionAnalysis.response_times.reduce((a, b) => a + b, 0) / connectionAnalysis.response_times.length);

        html += `
            <div class="finding-detail">
                <strong>Average Response Time:</strong> ${avgTime.toFixed(2)}ms
            </div>
        `;
    }

    if (connectionAnalysis.ssl_detected !== undefined) {
        html += `
            <div class="finding-detail">
                <strong>SSL/TLS Detected:</strong> ${connectionAnalysis.ssl_detected ? '✅ Yes' : '❌ No'}
            </div>
        `;
    }

    if (connectionAnalysis.connection_stability !== undefined) {
        html += `
            <div class="finding-detail">
                <strong>Connection Stability:</strong> ${connectionAnalysis.connection_stability ? '✅ Stable' : '⚠️ Unstable'}
            </div>
        `;
    }

    // Banner Analysis
    if (connectionAnalysis.banner_analysis) {
        const bannerAnalysis = connectionAnalysis.banner_analysis;
        html += `
            <div class="banner-analysis-subsection">
                <h6>📋 Banner Analysis</h6>
                <div class="finding-detail">
                    <strong>Server Software:</strong> ${safeDisplayValue(bannerAnalysis.server_software)}
                </div>
                <div class="finding-detail">
                    <strong>Version Disclosed:</strong> ${bannerAnalysis.version_disclosed ? '⚠️ Yes' : '✅ No'}
                </div>
                <div class="finding-detail">
                    <strong>Hostname Disclosed:</strong> ${bannerAnalysis.hostname_disclosed ? '⚠️ Yes' : '✅ No'}
                </div>
                ${bannerAnalysis.information_leakage && bannerAnalysis.information_leakage.length > 0 ? `
                    <div class="finding-detail">
                        <strong>Information Leakage:</strong>
                        <ul class="info-leakage-list">
                            ${bannerAnalysis.information_leakage.map(leak => `<li>${safeDisplayValue(leak)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatSMTPCommandTesting(commandTesting) {
    let html = `
        <div class="finding-section smtp-commands-section">
            <h5>⚙️ SMTP Command Testing</h5>
    `;

    if (commandTesting.supported_commands && commandTesting.supported_commands.length > 0) {
        html += `
            <div class="finding-detail">
                <strong>Supported Commands:</strong>
                <div class="smtp-commands-grid">
                    ${commandTesting.supported_commands.map(cmd => 
                        `<span class="smtp-command-item safe">${safeDisplayValue(cmd)}</span>`
                    ).join('')}
                </div>
            </div>
        `;
    }

    if (commandTesting.dangerous_commands && commandTesting.dangerous_commands.length > 0) {
        html += `
            <div class="finding-detail">
                <strong>⚠️ Dangerous Commands Enabled:</strong>
                <div class="smtp-commands-grid">
                    ${commandTesting.dangerous_commands.map(cmd => 
                        `<span class="smtp-command-item dangerous">${safeDisplayValue(cmd)}</span>`
                    ).join('')}
                </div>
            </div>
        `;
    }

    if (commandTesting.starttls_available !== undefined) {
        html += `
            <div class="finding-detail">
                <strong>STARTTLS Available:</strong> ${commandTesting.starttls_available ? '✅ Yes' : '❌ No'}
            </div>
        `;
    }

    // VRFY Testing Results
    if (commandTesting.vrfy_testing) {
        const vrfyResults = commandTesting.vrfy_testing;
        const vrfyEntries = Object.entries(vrfyResults);

        if (vrfyEntries.length > 0) {
            html += `
                <div class="vrfy-testing-subsection">
                    <h6>🔍 VRFY Command Testing</h6>
                    ${vrfyEntries.slice(0, 5).map(([user, result]) => `
                        <div class="finding-detail">
                            <strong>VRFY ${user}:</strong> 
                            ${result.error ? `Error: ${result.error}` : 
                              `Code ${result.code} - ${result.response?.substring(0, 100) || 'No response'}`}
                        </div>
                    `).join('')}
                    ${vrfyEntries.length > 5 ? `<div class="finding-detail"><em>... and ${vrfyEntries.length - 5} more tests</em></div>` : ''}
                </div>
            `;
        }
    }

    // EXPN Testing Results
    if (commandTesting.expn_testing) {
        html += `
            <div class="expn-testing-subsection">
                <h6>📤 EXPN Command Testing</h6>
                <div class="finding-detail">
                    <strong>EXPN Test:</strong> 
                    ${commandTesting.expn_testing.error ? 
                      `Error: ${commandTesting.expn_testing.error}` : 
                      `Code ${commandTesting.expn_testing.code} - ${commandTesting.expn_testing.response?.substring(0, 100) || 'No response'}`}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatSMTPRelayTesting(relayTesting) {
    let html = `
        <div class="finding-section smtp-relay-section">
            <h5>🔄 SMTP Relay Testing</h5>
    `;

    if (relayTesting.open_relay_detected !== undefined) {
        html += `
            <div class="finding-detail relay-status ${relayTesting.open_relay_detected ? 'critical' : 'good'}">
                <strong>Open Relay Status:</strong> 
                ${relayTesting.open_relay_detected ? '🚨 OPEN RELAY DETECTED' : '✅ No Open Relay'}
            </div>
        `;
    }

    if (relayTesting.open_relay_confidence) {
        const confidence = relayTesting.open_relay_confidence;
        const confidenceClass = confidence === 'high' ? 'critical' : confidence === 'medium' ? 'warning' : 'good';
        html += `
            <div class="finding-detail">
                <strong>Confidence Level:</strong> 
                <span class="confidence-${confidenceClass}">${confidence.toUpperCase()}</span>
            </div>
        `;
    }

    if (relayTesting.relay_patterns_tested) {
        html += `
            <div class="finding-detail">
                <strong>Relay Patterns Tested:</strong> ${relayTesting.relay_patterns_tested}
            </div>
        `;
    }

    // Basic Relay Results
    if (relayTesting.relay_results) {
        html += `
            <div class="relay-results-subsection">
                <h6>📋 Relay Test Results</h6>
        `;

        Object.entries(relayTesting.relay_results).forEach(([pattern, result]) => {
            const isAccepted = result.includes('ACCEPTED') || result.includes('250');
            html += `
                <div class="relay-test-item ${isAccepted ? 'accepted' : 'rejected'}">
                    <div class="relay-test-pattern">${safeDisplayValue(pattern)}</div>
                    <div class="relay-test-result">${safeDisplayValue(result)}</div>
                </div>
            `;
        });

        html += '</div>';
    }

    // Extensive Relay Results
    if (relayTesting.extensive_relay_tests) {
        html += `
            <div class="extensive-relay-subsection">
                <h6>📋 Extensive Relay Tests</h6>
        `;

        Object.entries(relayTesting.extensive_relay_tests).forEach(([pattern, result]) => {
            const isAccepted = result.includes('ACCEPTED') || result.includes('250');
            html += `
                <div class="relay-test-item ${isAccepted ? 'accepted' : 'rejected'}">
                    <div class="relay-test-pattern">${safeDisplayValue(pattern)}</div>
                    <div class="relay-test-result">${safeDisplayValue(result)}</div>
                </div>
            `;
        });

        html += '</div>';
    }

    html += '</div>';
    return html;
}

function formatSMTPUserEnumeration(userEnum) {
    let html = `
        <div class="finding-section smtp-user-enum-section">
            <h5>👥 User Enumeration Analysis</h5>
    `;

    if (userEnum.enumeration_methods && userEnum.enumeration_methods.length > 0) {
        html += `
            <div class="finding-detail">
                <strong>⚠️ Enumeration Methods Available:</strong>
                <div class="enum-methods">
                    ${userEnum.enumeration_methods.map(method => 
                        `<span class="method-badge dangerous">${safeDisplayValue(method)}</span>`
                    ).join('')}
                </div>
            </div>
        `;
    }

    if (userEnum.valid_users && userEnum.valid_users.length > 0) {
        html += `
            <div class="finding-detail">
                <strong>🚨 Valid Users Found:</strong>
                <div class="valid-users-list">
                    ${userEnum.valid_users.map(user => 
                        `<span class="user-badge">${safeDisplayValue(user)}</span>`
                    ).join('')}
                </div>
            </div>
        `;
    }

    if (userEnum.vrfy_enabled !== undefined || userEnum.expn_enabled !== undefined) {
        html += `
            <div class="finding-detail">
                <strong>Command Status:</strong>
                ${userEnum.vrfy_enabled !== undefined ? 
                  `<span class="command-status ${userEnum.vrfy_enabled ? 'enabled' : 'disabled'}">
                    VRFY: ${userEnum.vrfy_enabled ? 'Enabled ⚠️' : 'Disabled ✅'}
                  </span>` : ''}
                ${userEnum.expn_enabled !== undefined ? 
                  `<span class="command-status ${userEnum.expn_enabled ? 'enabled' : 'disabled'}">
                    EXPN: ${userEnum.expn_enabled ? 'Enabled ⚠️' : 'Disabled ✅'}
                  </span>` : ''}
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatSMTPTimingAnalysis(timingAnalysis) {
    let html = `
        <div class="finding-section smtp-timing-section">
            <h5>⏱️ Timing Analysis</h5>
    `;

    if (timingAnalysis.baseline_time) {
        html += `
            <div class="finding-detail">
                <strong>Baseline Response Time:</strong> ${timingAnalysis.baseline_time.toFixed(2)}ms
            </div>
        `;
    }

    if (timingAnalysis.potential_user_enum !== undefined) {
        html += `
            <div class="finding-detail">
                <strong>Timing-Based Enumeration Risk:</strong> 
                ${timingAnalysis.potential_user_enum ? 
                  '⚠️ Possible (timing differences detected)' : 
                  '✅ Low (consistent timing)'}
            </div>
        `;
    }

    if (timingAnalysis.timing_differences) {
        html += `
            <div class="timing-differences-subsection">
                <h6>📊 Timing Differences</h6>
        `;

        Object.entries(timingAnalysis.timing_differences).forEach(([username, data]) => {
            const difference = data.difference || 0;
            const isDifferent = Math.abs(difference) > 100; // 100ms threshold

            html += `
                <div class="timing-item ${isDifferent ? 'different' : 'normal'}">
                    <strong>${safeDisplayValue(username)}:</strong> 
                    ${data.response_time?.toFixed(2) || 'N/A'}ms 
                    (${difference > 0 ? '+' : ''}${difference.toFixed(2)}ms difference)
                </div>
            `;
        });

        html += '</div>';
    }

    html += '</div>';
    return html;
}



async function startDeepSMBScan(previousScanData) {
    console.log('🎯 Starting deep SMB scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(DEEP_SCAN_WARNINGS.smb.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep SMB scan');
        Utils.showNotification('Deep SMB scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep SMB scan - proceeding...');

    const deepBtn = document.getElementById('deepSMBScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All SMB Scripts + Brute Force...</span>
        `;
    }

    try {
        showDeepSMBScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'smb',
            normal_scan_results: previousScanData // Pass normal scan results for context
        };

        console.log('🚀 Starting deep SMB scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep SMB scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep SMB scan results:', deepResults);

        showDeepSMBResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep SMB scan error:', error);
        Utils.showNotification(`Deep SMB scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep SMB Scan (All Scripts + Brute Force)</span>
            `;
        }
    }
}

function showDeepSMBScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'SMB (Deep Scan - All Scripts + Brute Force)';
    }

    updateScanProgress(25, 'Loading comprehensive nmap SMB script suite...');

    setTimeout(() => updateScanProgress(50, 'Running smb-enum*, smb-vuln*, smb-brute scripts...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Analyzing deep SMB findings and brute force results...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep SMB scan completed'), 3000);
}


function showDeepSMBScanButton(scanData) {
    console.log('🔍 SMB Debug - showDeepSMBScanButton called with:', scanData);

    // Check if we have nmap data (since we're nmap-only now)
    const hasNmap = scanData.nmap_data && !scanData.nmap_data.error;

    console.log('🔍 SMB Debug - Nmap available check result:', hasNmap);

    if (!hasNmap) {
        console.log('🔍 SMB Debug - Deep SMB scan not available - nmap not available or failed');
        return;
    }

    // Check if button already exists
    const existingBtn = document.getElementById('deepSMBScanBtn');
    if (existingBtn) {
        existingBtn.remove();
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-smb-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep SMB Scan (All Scripts + Brute Force)</span>
    `;
    deepScanBtn.id = 'deepSMBScanBtn';
    deepScanBtn.onclick = () => startDeepSMBScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep SMB Scan button added successfully');
    }
}


function showDeepSMBResults(deepResults, originalResults) {
    console.log('🔍 Showing deep SMB scan results (nmap-only)');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep SMB Scan Results (All Scripts + Brute Force)
            <span class="deep-scan-badge">Complete</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show brute force results FIRST (most important)
    if (deepResults.advanced_findings && deepResults.advanced_findings.brute_force_results) {
        const bruteResults = deepResults.advanced_findings.brute_force_results;

        if (bruteResults.success && bruteResults.credentials_found && bruteResults.credentials_found.length > 0) {
            const credentialsCard = document.createElement('div');
            credentialsCard.className = 'result-card credentials-found-card critical-finding';
            credentialsCard.innerHTML = `
                <h4>🔓 SMB Credentials Discovered</h4>
                <div class="credentials-alert">
                    <div class="alert-icon">🚨</div>
                    <div class="alert-text">
                        <strong>CRITICAL SECURITY ISSUE:</strong> SMB brute force attack succeeded!
                    </div>
                </div>
                <div class="credentials-list">
                    ${bruteResults.credentials_found.map(cred => `
                        <div class="credential-item critical">
                            <div class="credential-header">
                                <span class="credential-type">🔐 SMB Account</span>
                                <span class="credential-status">✅ Verified</span>
                            </div>
                            <div class="credential-info">
                                <div class="credential-field">
                                    <strong>Credentials:</strong> 
                                    <code class="credential-value">${safeDisplayValue(cred)}</code>
                                </div>
                            </div>
                            <div class="credential-impact">
                                <span class="impact-item">📁 Can access SMB shares</span>
                                <span class="impact-item">🔒 Full SMB authentication</span>
                                <span class="impact-item">⚠️ Potential lateral movement</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
            resultsContent.appendChild(credentialsCard);
        } else if (bruteResults.brute_attempted) {
            const bruteCard = document.createElement('div');
            bruteCard.className = 'result-card brute-summary-card';
            bruteCard.innerHTML = `
                <h4>💥 SMB Brute Force Summary</h4>
                <div class="brute-summary-grid">
                    <div class="summary-stat">
                        <div class="stat-number">${bruteResults.brute_attempted ? 'Yes' : 'No'}</div>
                        <div class="stat-label">Brute Force Attempted</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">${bruteResults.success ? 'Success' : 'Failed'}</div>
                        <div class="stat-label">Result</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">0</div>
                        <div class="stat-label">Credentials Found</div>
                    </div>
                </div>
                <div class="brute-details">
                    <p><strong>Result:</strong> No credentials found with common passwords</p>
                    <p><em>💡 SMB server may have strong password policies or account lockout enabled</em></p>
                </div>
            `;
            resultsContent.appendChild(bruteCard);
        }
    }




    // Show raw nmap output (same as other scanners)
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep SMB Scan Output</h4>
            <div class="nmap-command-info">
                <strong>Command:</strong> ${deepResults.nmap_data.command_used || 'nmap -sV -sC -p445 --script "smb-enum*,smb-vuln*,smb-brute" -Pn -T4'}
            </div>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;
        resultsContent.appendChild(deepNmapCard);
    }

    // Update button (same pattern as other scanners)
    const deepBtn = document.getElementById('deepSMBScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    // Notification (same pattern as other scanners)
    const bruteResults = deepResults.advanced_findings?.brute_force_results;
    const credentialsFound = bruteResults?.credentials_found?.length || 0;

    if (credentialsFound > 0) {
        Utils.showNotification(`🚨 CRITICAL: ${credentialsFound} SMB credentials discovered!`, 'error');
    } else {
        Utils.showNotification('Deep SMB scan with brute force completed', 'success');
    }

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}


function showScanResults(scanData) {
    console.log('🔍 Showing scan results:', scanData);

    const resultsSection = document.getElementById('scanResults');
    const resultsContent = document.getElementById('resultsContent');

    if (!resultsSection || !resultsContent) return;

    hideCancelButton();
    currentScanData = scanData;
    resultsSection.classList.remove('hidden');

    // Check if scan failed
    if (scanData.status === 'failed') {
        resultsContent.innerHTML = renderFailedScanResults(scanData);
        setTimeout(() => {
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }, 300);
        return;
    }

    // Build results HTML for successful scans - CLEANED VERSION
    let resultsHTML = '';

    // **ONLY KEEP: SSH audit results for SSH scans**
    if (scanData.service_type === 'ssh' && scanData.ssh_audit_data) {
        resultsHTML += addEnhancedSSHAuditDisplay(scanData);
    }

    // **ONLY KEEP: Service-specific nmap results with proper error handling**
    if (scanData.nmap_data) {
        if (scanData.nmap_data.error) {
            resultsHTML += `
                <div class="result-card">
                    <h4>🔍 ${scanData.service_type?.toUpperCase() || 'Service'} Enhanced Scan Status</h4>
                    <div class="nmap-error">
                        <div class="error-content">
                            <div class="error-icon">⚠️</div>
                            <div class="error-details">
                                <p><strong>Enhanced scan encountered an issue:</strong></p>
                                <p class="error-message">${safeDisplayValue(scanData.nmap_data.error)}</p>
                                <p class="error-note"><em>Scanner used fallback analysis methods to provide basic results</em></p>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            // **KEEP: Proper nmap output display for all service types**
            const scanMode = scanData.nmap_data.scan_type || 'normal';
            const commandUsed = scanData.nmap_data.command_used || `nmap security scan for ${scanData.service_type}`;
            const serviceTypeUpper = (scanData.service_type || 'service').toUpperCase();

            resultsHTML += `
                <div class="result-card nmap-results-card">
                    <h4>🎯 ${serviceTypeUpper} Security Scan Results</h4>
                    <div class="scan-info">
                        <div class="scan-mode-indicator ${scanMode}">
                            <span class="mode-badge">${scanMode.toUpperCase()} SCAN</span>
                            <span class="mode-description">
                                Enhanced ${serviceTypeUpper} security assessment using nmap NSE scripts
                            </span>
                        </div>
                    </div>
                    
                    <div class="nmap-display">
                        <div class="nmap-command">
                            <strong>🔧 Command Used:</strong> 
                            <code class="command-text">${Utils.escapeHtml(commandUsed)}</code>
                        </div>
                        
                        <div class="nmap-output">
                            <h6>📋 Security Analysis Results:</h6>
                            
                            ${scanData.nmap_data.formatted_for_display ? `
                                <div class="nmap-formatted-output">
                                    <pre class="nmap-formatted">${Utils.escapeHtml(scanData.nmap_data.formatted_for_display)}</pre>
                                </div>
                            ` : ''}
                            
                            ${scanData.nmap_data.raw_output ? `
                                <details class="nmap-full-output">
                                    <summary>
                                        <span class="summary-icon">🔍</span>
                                        <span class="summary-text">View Complete Nmap Output</span>
                                        <span class="summary-hint">(Click to expand raw results)</span>
                                    </summary>
                                    <div class="nmap-raw-container">
                                        <pre class="nmap-raw">${Utils.escapeHtml(scanData.nmap_data.raw_output)}</pre>
                                    </div>
                                </details>
                            ` : `
                                <div class="no-raw-output">
                                    <p><em>No detailed output available from this scan</em></p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>
            `;
        }
    }

    // **KEEP: Advanced findings section - but only for non-SSH services**
    if (scanData.service_type !== 'ssh' && scanData.advanced_findings && hasValidAdvancedFindings(scanData.advanced_findings)) {
        let advancedHTML = '';

        switch(scanData.service_type) {
            case 'http':
                advancedHTML = formatHTTPAdvancedFindings(scanData.advanced_findings);
                break;
            case 'https':
                advancedHTML = formatHTTPSAdvancedFindings(scanData.advanced_findings);
                break;
            case 'smtp':
                advancedHTML = formatSMTPAdvancedFindings(scanData.advanced_findings);
                break;
            case 'smb':
                advancedHTML = formatSMBAdvancedFindings(scanData.advanced_findings);
                break;
            case 'snmp':
                advancedHTML = formatSNMPAdvancedFindings(scanData.advanced_findings);
                break;
            case 'ftp':
                advancedHTML = formatFTPFindings(scanData.advanced_findings);
                break;
            default:
                advancedHTML = formatAdvancedFindings(scanData.advanced_findings, scanData.service_type);
        }

        if (advancedHTML) {
            resultsHTML += `
                <div class="result-card advanced-findings-card">
                    <h4>🚀 Advanced ${scanData.service_type?.toUpperCase()} Analysis</h4>
                    <div class="advanced-findings">
                        ${advancedHTML}
                    </div>
                </div>
            `;
        }
    }

    // **KEEP: CVE Analysis section - but only for non-SSH services**
    if (scanData.service_type !== 'ssh' && scanData.cve_analysis && hasValidCVEData(scanData.cve_analysis)) {
        resultsHTML += renderCVEAnalysisCard(scanData.cve_analysis);
    }

    // **KEEP: Vulnerabilities section - but only for non-SSH services**
    if (scanData.service_type !== 'ssh') {
        const vulnerabilities = scanData.vulnerabilities || [];
        if (vulnerabilities.length > 0) {
            resultsHTML += renderEnhancedVulnerabilitiesCard(vulnerabilities);
        } else {
            resultsHTML += `
                <div class="result-card security-status-card">
                    <h4>🛡️ Security Assessment Summary</h4>
                    <div class="no-vulnerabilities">
                        <div class="success-icon">✅</div>
                        <div class="success-content">
                            <h5>No Immediate Security Issues Detected</h5>
                            <p>The ${scanData.service_type?.toUpperCase() || 'service'} security assessment completed without finding critical vulnerabilities.</p>
                            <div class="assessment-scope">
                                <strong>Assessment covered:</strong>
                                <ul>
                                    <li>Service configuration analysis</li>
                                    <li>Protocol security evaluation</li>
                                    <li>Common vulnerability checks</li>
                                    ${scanData.service_type === 'https' ? '<li>SSL/TLS certificate validation</li>' : ''}
                                    ${scanData.service_type === 'smtp' ? '<li>Mail server configuration review</li>' : ''}
                                </ul>
                            </div>
                            <div class="security-note">
                                <em>Note: This represents the current scan results. Regular security assessments are recommended.</em>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    // **KEEP: Security recommendations - but only for non-SSH services**
    if (scanData.service_type !== 'ssh' && scanData.recommendations && scanData.recommendations.length > 0) {
        resultsHTML += renderRecommendationsCard(scanData.recommendations);
    }

    resultsContent.innerHTML = resultsHTML;

    // **KEEP: Deep Scan buttons for ALL supported services when scan completes successfully**
    if (scanData.status === 'completed' && scanData.nmap_data && !scanData.nmap_data.error) {
        setTimeout(() => {
            switch(scanData.service_type) {
                case 'ftp':
                    if (typeof showDeepFTPScanButton === 'function') {
                        showDeepFTPScanButton(scanData);
                        console.log('✅ Deep FTP Scan button added');
                    }
                    break;
                case 'ssh':
                    if (typeof showDeepSSHScanButton === 'function') {
                        showDeepSSHScanButton(scanData);
                        console.log('✅ Deep SSH Scan button added');
                    }
                    break;
                case 'smtp':
                    if (typeof showDeepSMTPScanButton === 'function') {
                        showDeepSMTPScanButton(scanData);
                        console.log('✅ Deep SMTP Scan button added');
                    }
                    break;
                case 'smb':
                    if (typeof showDeepSMBScanButton === 'function') {
                        showDeepSMBScanButton(scanData);
                        console.log('✅ Deep SMB Scan button added');
                    }
                    break;
                case 'snmp':
                    if (typeof showDeepSNMPScanButton === 'function') {
                        showDeepSNMPScanButton(scanData);
                        console.log('✅ Deep SNMP Scan button added');
                    }
                    break;
                case 'http':
                    if (typeof showDeepHTTPScanButton === 'function') {
                        showDeepHTTPScanButton(scanData);
                        console.log('✅ Deep HTTP Scan button added');
                    }
                    break;
                case 'https':
                    if (typeof showDeepHTTPSScanButton === 'function') {
                        showDeepHTTPSScanButton(scanData);
                        console.log('✅ Deep HTTPS Scan button added');
                    }
                    break;
                default:
                    console.log(`⚠️ No deep scan available for service type: ${scanData.service_type}`);
            }
        }, 100);
    }

    // Scroll to results
    setTimeout(() => {
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }, 300);

    console.log('✅ CLEANED Results displayed successfully for:', scanData.service_type);
}

// Additional function to specifically handle SSH results display
function showSSHScanResultsClean(scanData) {
    console.log('🔍 Showing CLEAN SSH scan results:', scanData);

    const resultsSection = document.getElementById('scanResults');
    const resultsContent = document.getElementById('resultsContent');

    if (!resultsSection || !resultsContent) return;

    hideCancelButton();
    currentScanData = scanData;
    resultsSection.classList.remove('hidden');

    // For SSH scans, ONLY show SSH audit results
    let resultsHTML = '';

    if (scanData.ssh_audit_data) {
        resultsHTML = addEnhancedSSHAuditDisplay(scanData);
    } else {
        resultsHTML = `
            <div class="result-card">
                <h4>🔐 SSH Security Assessment</h4>
                <div class="ssh-basic-info">
                    <p>SSH service detected but detailed security analysis is not available.</p>
                    <p><strong>Status:</strong> ${scanData.status || 'Unknown'}</p>
                    ${scanData.banner ? `<p><strong>Banner:</strong> ${scanData.banner}</p>` : ''}
                </div>
            </div>
        `;
    }

    resultsContent.innerHTML = resultsHTML;

    // Add deep scan button if available
    if (scanData.status === 'completed' && scanData.nmap_data && !scanData.nmap_data.error) {
        setTimeout(() => {
            if (typeof showDeepSSHScanButton === 'function') {
                showDeepSSHScanButton(scanData);
                console.log('✅ Deep SSH Scan button added');
            }
        }, 100);
    }

    // Scroll to results
    setTimeout(() => {
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }, 300);

    console.log('✅ CLEANED SSH Results displayed successfully');
}

// Function to clean up existing results and use cleaned version
function cleanupSSHResults() {
    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Remove specific divs that are redundant
    const divsToRemove = [
        '.enhanced-security-assessment',
        '.advanced-ssh-analysis',
        '.ssh-security-scan-results',
        '.complete-service-info',
        '.complete-technical-analysis',
        '.security-assessment-score'
    ];

    divsToRemove.forEach(selector => {
        const elements = resultsContent.querySelectorAll(selector);
        elements.forEach(element => {
            console.log(`🗑️ Removing redundant div: ${selector}`);
            element.remove();
        });
    });

    // Also remove any result-cards that contain these specific headers
    const resultCards = resultsContent.querySelectorAll('.result-card');
    resultCards.forEach(card => {
        const header = card.querySelector('h4');
        if (header) {
            const headerText = header.textContent.toLowerCase();
            if (headerText.includes('enhanced security assessment') ||
                headerText.includes('complete service information') ||
                headerText.includes('complete technical analysis') ||
                headerText.includes('advanced ssh analysis') ||
                headerText.includes('security assessment score')) {
                console.log(`🗑️ Removing redundant card: ${headerText}`);
                card.remove();
            }
        }
    });
}

console.log('✅ Cleaned SSH display functions loaded - removes redundant sections');


function extractCertificateInfo(serviceInfo) {
    const certInfo = {};

    for (const [key, value] of Object.entries(serviceInfo)) {
        if (key.startsWith('certificate_') && value !== null && value !== undefined) {
            certInfo[key] = value;
        }
    }

    return certInfo;
}

function formatCertificateAnalysis(certInfo) {
    let html = '<div class="certificate-info-grid">';

    // Certificate validity status
    if (certInfo.certificate_valid !== undefined) {
        html += `
            <div class="cert-info-item ${certInfo.certificate_valid ? 'valid' : 'invalid'}">
                <div class="cert-label">Certificate Status</div>
                <div class="cert-value">${certInfo.certificate_valid ? '✅ Valid' : '❌ Invalid'}</div>
            </div>
        `;
    }

    // Certificate expiration
    if (certInfo.certificate_expired !== undefined) {
        html += `
            <div class="cert-info-item ${certInfo.certificate_expired ? 'expired' : 'valid'}">
                <div class="cert-label">Expiration Status</div>
                <div class="cert-value">${certInfo.certificate_expired ? '⚠️ Expired' : '✅ Valid'}</div>
            </div>
        `;
    }

    // Self-signed status
    if (certInfo.certificate_self_signed !== undefined) {
        html += `
            <div class="cert-info-item ${certInfo.certificate_self_signed ? 'warning' : 'good'}">
                <div class="cert-label">Certificate Authority</div>
                <div class="cert-value">${certInfo.certificate_self_signed ? '⚠️ Self-Signed' : '✅ CA Issued'}</div>
            </div>
        `;
    }

    // Certificate dates
    if (certInfo.certificate_not_after) {
        html += `
            <div class="cert-info-item">
                <div class="cert-label">Expires</div>
                <div class="cert-value">${safeDisplayValue(certInfo.certificate_not_after)}</div>
            </div>
        `;
    }

    // Certificate subject
    if (certInfo.certificate_subject) {
        const subject = certInfo.certificate_subject;
        if (typeof subject === 'object') {
            const commonName = subject.commonName || subject.CN || 'Not specified';
            html += `
                <div class="cert-info-item">
                    <div class="cert-label">Common Name</div>
                    <div class="cert-value">${safeDisplayValue(commonName)}</div>
                </div>
            `;
        }
    }

    // Certificate issuer
    if (certInfo.certificate_issuer) {
        const issuer = certInfo.certificate_issuer;
        if (typeof issuer === 'object') {
            const issuerName = issuer.organizationName || issuer.commonName || issuer.CN || 'Unknown';
            html += `
                <div class="cert-info-item">
                    <div class="cert-label">Issued By</div>
                    <div class="cert-value">${safeDisplayValue(issuerName)}</div>
                </div>
            `;
        }
    }

    // Subject Alternative Names
    if (certInfo.certificate_sans && Array.isArray(certInfo.certificate_sans)) {
        const sansList = certInfo.certificate_sans.map(san => Array.isArray(san) ? san[1] : san).join(', ');
        html += `
            <div class="cert-info-item">
                <div class="cert-label">Subject Alt Names</div>
                <div class="cert-value">${safeDisplayValue(sansList)}</div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatHTTPSAdvancedFindings(findings) {
    let html = '<div class="https-advanced-findings-content">';

    // SSL Analysis
    if (findings.ssl_analysis) {
        html += formatSSLSecurityAnalysis(findings.ssl_analysis);
    }

    // Web Analysis
    if (findings.web_analysis) {
        html += formatWebSecurityAnalysis(findings.web_analysis);
    }

    html += '</div>';
    return html;
}

// Helper function to format SSL security analysis
function formatSSLSecurityAnalysis(sslAnalysis) {
    let html = `
        <div class="finding-section ssl-security-analysis">
            <h5>🔒 SSL/TLS Security Analysis</h5>
    `;

    if (sslAnalysis.certificate_info) {
        html += `
            <div class="ssl-finding-item">
                <strong>Certificate Information:</strong>
                <div class="ssl-cert-details">${safeDisplayValue(sslAnalysis.certificate_info)}</div>
            </div>
        `;
    }

    if (sslAnalysis.cipher_analysis) {
        html += `
            <div class="ssl-finding-item">
                <strong>Cipher Suite Analysis:</strong>
                <div class="ssl-cipher-details">${safeDisplayValue(sslAnalysis.cipher_analysis)}</div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// Helper function to format web security analysis
function formatWebSecurityAnalysis(webAnalysis) {
    let html = `
        <div class="finding-section web-security-analysis">
            <h5>🌐 Web Security Analysis</h5>
    `;

    if (webAnalysis.security_headers) {
        html += `
            <div class="web-finding-item">
                <strong>Security Headers:</strong>
                <div class="security-headers-details">${formatSecurityHeaders(webAnalysis.security_headers)}</div>
            </div>
        `;
    }

    if (webAnalysis.server_info) {
        html += `
            <div class="web-finding-item">
                <strong>Server Information:</strong>
                <div class="server-info-details">${safeDisplayValue(webAnalysis.server_info)}</div>
            </div>
        `;
    }

    if (webAnalysis.directories_found) {
        html += `
            <div class="web-finding-item">
                <strong>Directories Found:</strong>
                <div class="directories-details">${safeDisplayValue(webAnalysis.directories_found)}</div>
            </div>
        `;
    }

    if (webAnalysis.backup_files) {
        html += `
            <div class="web-finding-item">
                <strong>Backup Files Found:</strong>
                <div class="backup-files-details">${safeDisplayValue(webAnalysis.backup_files)}</div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function hasValidCVEData(cveAnalysis) {
    if (!cveAnalysis || typeof cveAnalysis !== 'object') return false;

    const excludeKeys = ['scan_status'];
    const meaningfulKeys = Object.keys(cveAnalysis).filter(key =>
        !excludeKeys.includes(key) &&
        cveAnalysis[key] !== null &&
        cveAnalysis[key] !== undefined &&
        cveAnalysis[key] !== ''
    );

    return meaningfulKeys.length > 0;
}

function renderCVEAnalysisCard(cveAnalysis) {
    return `
        <div class="result-card">
            <h4>🔍 CVE Analysis</h4>
            <div class="cve-analysis-content">
                ${formatAdvancedFindings(cveAnalysis, 'cve')}
            </div>
        </div>
    `;
}


// Enhanced safeDisplayValue function with better error handling
function safeDisplayValue(value) {
    try {
        // Handle null, undefined, empty
        if (value === null || value === undefined || value === '') {
            return '';
        }

        // Handle strings
        if (typeof value === 'string') {
            return value.trim();
        }

        // Handle numbers
        if (typeof value === 'number') {
            return value.toString();
        }

        // Handle booleans
        if (typeof value === 'boolean') {
            return value ? 'Yes' : 'No';
        }

        // Handle arrays
        if (Array.isArray(value)) {
            if (value.length === 0) return '';

            // If array of simple values, join them
            if (value.every(item => typeof item === 'string' || typeof item === 'number')) {
                return value.slice(0, 3).join(', ') + (value.length > 3 ? ` (+${value.length - 3} more)` : '');
            }

            // For complex arrays, show count
            return `${value.length} items`;
        }

        // Handle objects
        if (typeof value === 'object' && value !== null) {
            // Try to find a meaningful display value
            if (value.name) return safeDisplayValue(value.name);
            if (value.title) return safeDisplayValue(value.title);
            if (value.value) return safeDisplayValue(value.value);
            if (value.text) return safeDisplayValue(value.text);

            // For objects with few properties, show key-value pairs
            const entries = Object.entries(value);
            if (entries.length <= 3) {
                return entries
                    .map(([k, v]) => `${k}: ${safeDisplayValue(v)}`)
                    .join(', ');
            }

            // Otherwise, show object summary
            return `{${entries.length} properties}`;
        }

        // Fallback - convert to string but avoid [object Object]
        const stringValue = String(value);
        if (stringValue === '[object Object]') {
            return JSON.stringify(value).substring(0, 50) + '...';
        }
        return stringValue;
    } catch (error) {
        console.error('Error in safeDisplayValue:', error);
        return 'Unable to display value';
    }
}

function formatSMBServiceInfo(serviceInfo, serviceType) {
    let html = '';

    // Basic SMB service information
    if (serviceInfo.service_name || serviceType) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Type:</span>
                <span class="service-value">${serviceInfo.service_name || serviceType.toUpperCase()}</span>
            </div>
        `;
    }

    if (serviceInfo.server_type) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SMB Server:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.server_type)}</span>
            </div>
        `;
    }

    if (serviceInfo.version || serviceInfo.service_version) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Version:</span>
                <span class="service-value">${serviceInfo.version || serviceInfo.service_version}</span>
            </div>
        `;
    }

    if (serviceInfo.banner) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SMB Banner:</span>
                <span class="service-value banner-text">${safeDisplayValue(serviceInfo.banner)}</span>
            </div>
        `;
    }

    // SMB-specific fields
    if (serviceInfo.signing_status) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SMB Signing:</span>
                <span class="service-value">${safeDisplayValue(serviceInfo.signing_status)}</span>
            </div>
        `;
    }

    if (serviceInfo.smb_versions_detected && serviceInfo.smb_versions_detected.length > 0) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">SMB Versions:</span>
                <span class="service-value">${serviceInfo.smb_versions_detected.join(', ')}</span>
            </div>
        `;
    }

    // Response time
    if (serviceInfo.response_time_ms || serviceInfo.connection_time) {
        const responseTime = serviceInfo.response_time_ms || serviceInfo.connection_time;
        html += `
            <div class="service-detail-row">
                <span class="service-label">Response Time:</span>
                <span class="service-value">${responseTime}ms</span>
            </div>
        `;
    }

    if (serviceInfo.accessible !== undefined) {
        html += `
            <div class="service-detail-row">
                <span class="service-label">Service Accessible:</span>
                <span class="service-value">${serviceInfo.accessible ? '✅ Yes' : '❌ No'}</span>
            </div>
        `;
    }

    // Fallback content if nothing was added
    if (!html.trim()) {
        html = `
            <div class="service-detail-row">
                <span class="service-label">Service Detected:</span>
                <span class="service-value">${serviceType.toUpperCase()} service is running</span>
            </div>
            <div class="service-detail-row">
                <span class="service-label">Port Status:</span>
                <span class="service-value">✅ Open and Accessible</span>
            </div>
        `;
    }

    return html;
}

function renderSMBVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'smb_scanner';

    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap') || vuln.detection_method?.includes('smb-')) {
        badgeText = 'NMAP NSE';
        badgeClass = 'nmap-badge';
    } else if (source.includes('deep_scan_attack')) {
        badgeText = 'DEEP SCAN';
        badgeClass = 'deep-scan-badge';
    } else if (source.includes('wsl')) {
        badgeText = 'WSL TOOLS';
        badgeClass = 'wsl-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} smb-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'SMB-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                    ${vuln.cvss_score ? `<span class="cvss-score">CVSS: ${vuln.cvss_score}</span>` : ''}
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'SMB Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}


function formatSMBProtocolAnalysis(protocolInfo) {
    let html = '<div class="smb-protocol-container">';

    // Connection Analysis
    if (protocolInfo.connection_test_successful !== undefined) {
        html += `
            <div class="smb-section">
                <h5>🔌 Connection Status</h5>
                <div class="smb-status-item ${protocolInfo.connection_test_successful ? 'good' : 'critical'}">
                    <div class="smb-status-label">Connection</div>
                    <div class="smb-status-value">${protocolInfo.connection_test_successful ? '✅ Successful' : '❌ Failed'}</div>
                </div>
            </div>
        `;
    }

    // SMB Versions
    if (protocolInfo.smb_versions_detected && protocolInfo.smb_versions_detected.length > 0) {
        html += `
            <div class="smb-section">
                <h5>📋 SMB Versions Detected</h5>
                <div class="smb-versions-list">
                    ${protocolInfo.smb_versions_detected.map(version => `
                        <span class="smb-version-badge">${safeDisplayValue(version)}</span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // Signing Status
    if (protocolInfo.signing_status && protocolInfo.signing_status !== 'unknown') {
        const isSecure = protocolInfo.signing_status.toLowerCase().includes('required') ||
                        protocolInfo.signing_status.toLowerCase().includes('enabled');
        html += `
            <div class="smb-section">
                <h5>🔒 SMB Signing Status</h5>
                <div class="smb-status-item ${isSecure ? 'good' : 'warning'}">
                    <div class="smb-status-label">Signing</div>
                    <div class="smb-status-value">${safeDisplayValue(protocolInfo.signing_status)}</div>
                </div>
            </div>
        `;
    }

    // Null Session Test Results
    if (protocolInfo.null_session_test && protocolInfo.null_session_test !== 'not_attempted') {
        const isVulnerable = protocolInfo.null_session_test === 'successful';
        html += `
            <div class="smb-section">
                <h5>🔓 Null Session Test</h5>
                <div class="smb-status-item ${isVulnerable ? 'critical' : 'good'}">
                    <div class="smb-status-label">Null Session</div>
                    <div class="smb-status-value">${isVulnerable ? '⚠️ Vulnerable' : '✅ Protected'}</div>
                </div>
            </div>
        `;
    }

    // Guest Access Test Results
    if (protocolInfo.guest_access_test && protocolInfo.guest_access_test !== 'not_attempted') {
        const isVulnerable = protocolInfo.guest_access_test === 'successful';
        html += `
            <div class="smb-section">
                <h5>👤 Guest Access Test</h5>
                <div class="smb-status-item ${isVulnerable ? 'warning' : 'good'}">
                    <div class="smb-status-label">Guest Access</div>
                    <div class="smb-status-value">${isVulnerable ? '⚠️ Enabled' : '✅ Disabled'}</div>
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// 5. ADD SMB advanced findings formatter

function formatSMBAdvancedFindings(findings) {
    let html = '<div class="smb-advanced-findings-content">';

    // OS Discovery Results (parsed from nmap output)
    if (findings.os_discovery) {
        html += formatSMBOSDiscovery(findings.os_discovery);
    }

    // Security Mode Results (parsed from nmap output)
    if (findings.security_mode) {
        html += formatSMBSecurityMode(findings.security_mode);
    }



    // Vulnerability Findings (aggressive mode - parsed from nmap output)
    if (findings.vulnerability_findings) {
        html += formatSMBVulnerabilityFindings(findings.vulnerability_findings);
    }
    // Brute Force Results (aggressive mode - parsed from nmap output)
    if (findings.brute_force_results) {
        html += formatSMBBruteForceResults(findings.brute_force_results);
    }

    html += '</div>';
    return html;
}

function formatSMBOSDiscovery(osDiscovery) {
    return `
        <div class="finding-section smb-os-discovery">
            <h5>🖥️ Operating System Discovery</h5>
            <div class="os-discovery-status ${osDiscovery.os_detected ? 'detected' : 'not-detected'}">
                Status: ${osDiscovery.os_detected ? '✅ OS Information Found' : '❌ No OS Information'}
            </div>
            ${osDiscovery.os_detected ? `
                <div class="os-discovery-details">
                    ${osDiscovery.computer_name ? `
                        <div class="os-detail">
                            <strong>Computer Name:</strong> ${safeDisplayValue(osDiscovery.computer_name)}
                        </div>
                    ` : ''}
                    ${osDiscovery.domain ? `
                        <div class="os-detail">
                            <strong>Domain:</strong> ${safeDisplayValue(osDiscovery.domain)}
                        </div>
                    ` : ''}
                    ${osDiscovery.workgroup ? `
                        <div class="os-detail">
                            <strong>Workgroup:</strong> ${safeDisplayValue(osDiscovery.workgroup)}
                        </div>
                    ` : ''}
                    ${osDiscovery.fqdn ? `
                        <div class="os-detail">
                            <strong>FQDN:</strong> ${safeDisplayValue(osDiscovery.fqdn)}
                        </div>
                    ` : ''}
                </div>
            ` : ''}
        </div>
    `;
}

function formatSMBSecurityMode(securityMode) {
    const signingSecure = securityMode.message_signing === 'required';
    return `
        <div class="finding-section smb-security-mode">
            <h5>🔒 SMB Security Configuration</h5>
            <div class="security-mode-grid">
                <div class="security-setting ${signingSecure ? 'secure' : 'insecure'}">
                    <div class="setting-label">Message Signing</div>
                    <div class="setting-value">${safeDisplayValue(securityMode.message_signing)}</div>
                </div>
                ${securityMode.smb_version ? `
                    <div class="security-setting">
                        <div class="setting-label">SMB Version</div>
                        <div class="setting-value">${safeDisplayValue(securityMode.smb_version)}</div>
                    </div>
                ` : ''}
                <div class="security-setting">
                    <div class="setting-label">Authentication</div>
                    <div class="setting-value">${safeDisplayValue(securityMode.authentication)}</div>
                </div>
            </div>
            ${!signingSecure ? `
                <div class="security-warning">
                    ⚠️ SMB signing not required - vulnerable to relay attacks
                </div>
            ` : ''}
        </div>
    `;
}

x``
function formatSMBVulnerabilityFindings(vulnFindings) {
    const vulnEntries = Object.entries(vulnFindings);
    const criticalVulns = vulnEntries.filter(([script, result]) =>
        result.toLowerCase().includes('vulnerable') || result.toLowerCase().includes('ms17-010'));

    return `
        <div class="finding-section smb-vulnerability-findings">
            <h5>🛡️ Vulnerability Assessment Results</h5>
            <div class="vuln-findings-summary">
                <div class="vuln-stats">
                    <div class="vuln-stat">
                        <span class="stat-number">${vulnEntries.length}</span>
                        <span class="stat-label">Scripts Run</span>
                    </div>
                    <div class="vuln-stat ${criticalVulns.length > 0 ? 'critical' : 'secure'}">
                        <span class="stat-number">${criticalVulns.length}</span>
                        <span class="stat-label">Vulnerabilities</span>
                    </div>
                </div>
            </div>
            <div class="vuln-findings-list">
                ${vulnEntries.map(([scriptName, result]) => {
                    const isVulnerable = result.toLowerCase().includes('vulnerable') || 
                                       result.toLowerCase().includes('risk');
                    const isCritical = scriptName.includes('ms17-010') || scriptName.includes('eternalblue');
                    
                    return `
                        <div class="vuln-finding-item ${isVulnerable ? (isCritical ? 'critical' : 'vulnerable') : 'secure'}">
                            <div class="vuln-script-header">
                                <span class="vuln-script-name">🎯 ${scriptName}</span>
                                <span class="vuln-status ${isVulnerable ? 'vulnerable' : 'secure'}">
                                    ${isVulnerable ? '⚠️ VULNERABLE' : '✅ SECURE'}
                                </span>
                            </div>
                            <div class="vuln-script-result">
                                ${safeDisplayValue(result)}
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    `;
}



function formatSMBBruteForceResults(bruteResults) {
    const hasCredentials = bruteResults.success && bruteResults.credentials_found && bruteResults.credentials_found.length > 0;

    return `
        <div class="finding-section smb-brute-force ${hasCredentials ? 'critical' : 'secure'}">
            <h5>🔐 SMB Brute Force Results</h5>
            <div class="brute-force-status ${hasCredentials ? 'success' : 'failed'}">
                Status: ${hasCredentials ? '🚨 CREDENTIALS FOUND' : '✅ NO CREDENTIALS FOUND'}
            </div>
            ${hasCredentials ? `
                <div class="brute-credentials-alert">
                    <div class="alert-header">
                        <span class="alert-icon">🚨</span>
                        <span class="alert-title">CRITICAL: SMB Credentials Discovered</span>
                    </div>
                    <div class="credentials-list">
                        ${bruteResults.credentials_found.map(cred => `
                            <div class="credential-item">
                                <strong>Found:</strong> <code>${safeDisplayValue(cred)}</code>
                            </div>
                        `).join('')}
                    </div>
                    <div class="security-impact">
                        <strong>Security Impact:</strong>
                        <ul>
                            <li>Full SMB authentication possible</li>
                            <li>Access to SMB shares and resources</li>
                            <li>Potential for lateral movement</li>
                            <li>Password reuse across other services</li>
                        </ul>
                    </div>
                </div>
            ` : `
                <div class="no-credentials">
                    <p>✅ Brute force attack did not succeed with common passwords.</p>
                    <p><em>This indicates strong password policies or account lockout mechanisms.</em></p>
                </div>
            `}
        </div>
    `;
}





function formatSMBNullSessionResults(nullResults) {
    return `
        <div class="finding-section smb-null-session">
            <h5>🔓 Null Session Analysis</h5>
            <div class="null-session-status ${nullResults.successful ? 'vulnerable' : 'secure'}">
                Status: ${nullResults.successful ? '⚠️ VULNERABLE' : '✅ PROTECTED'}
            </div>
            ${nullResults.successful ? `
                <div class="null-session-details">
                    <p><strong>Method:</strong> ${safeDisplayValue(nullResults.method_used)}</p>
                    ${nullResults.shares_found && nullResults.shares_found.length > 0 ? `
                        <div class="accessible-shares">
                            <strong>Accessible Shares:</strong>
                            <div class="shares-grid">
                                ${nullResults.shares_found.map(share => `
                                    <span class="share-badge accessible">${safeDisplayValue(share)}</span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                    ${nullResults.users_found && nullResults.users_found.length > 0 ? `
                        <div class="enumerated-users">
                            <strong>Enumerated Users:</strong>
                            <div class="users-grid">
                                ${nullResults.users_found.map(user => `
                                    <span class="user-badge enumerated">${safeDisplayValue(user)}</span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            ` : ''}
        </div>
    `;
}

function formatSMBEternalBlueResults(eternalResults) {
    return `
        <div class="finding-section smb-eternalblue ${eternalResults.vulnerable ? 'critical' : 'secure'}">
            <h5>💥 EternalBlue Vulnerability Test</h5>
            <div class="eternalblue-status ${eternalResults.vulnerable ? 'vulnerable' : 'secure'}">
                Status: ${eternalResults.vulnerable ? '🚨 VULNERABLE' : '✅ NOT VULNERABLE'}
            </div>
            ${eternalResults.vulnerable ? `
                <div class="eternalblue-critical-alert">
                    <div class="alert-header">
                        <span class="alert-icon">💥</span>
                        <span class="alert-title">CRITICAL VULNERABILITY DETECTED</span>
                    </div>
                    <div class="vulnerability-details">
                        <p><strong>CVE:</strong> CVE-2017-0144</p>
                        <p><strong>CVSS Score:</strong> ${eternalResults.cvss_score || '9.3'}</p>
                        <p><strong>Test Method:</strong> ${safeDisplayValue(eternalResults.test_method)}</p>
                        <p><strong>Impact:</strong> Remote Code Execution</p>
                    </div>
                    <div class="urgent-recommendation">
                        <strong>🚨 URGENT:</strong> Apply Microsoft Security Bulletin MS17-010 immediately!
                    </div>
                </div>
            ` : `
                <div class="eternalblue-secure">
                    <p>System appears to be patched against EternalBlue exploit.</p>
                    <p><strong>Test Method:</strong> ${safeDisplayValue(eternalResults.test_method)}</p>
                </div>
            `}
        </div>
    `;
}

function formatSMBShareAnalysisResults(shareResults) {
    return `
        <div class="finding-section smb-share-analysis">
            <h5>📁 SMB Share Analysis</h5>
            <div class="share-analysis-summary">
                <div class="share-stats-grid">
                    <div class="share-stat">
                        <span class="stat-number">${shareResults.shares_analyzed || 0}</span>
                        <span class="stat-label">Analyzed</span>
                    </div>
                    <div class="share-stat readable">
                        <span class="stat-number">${shareResults.readable_shares?.length || 0}</span>
                        <span class="stat-label">Readable</span>
                    </div>
                    <div class="share-stat writable">
                        <span class="stat-number">${shareResults.writable_shares?.length || 0}</span>
                        <span class="stat-label">Writable</span>
                    </div>
                </div>
            </div>
            ${shareResults.readable_shares && shareResults.readable_shares.length > 0 ? `
                <div class="readable-shares">
                    <h6>📖 Readable Shares:</h6>
                    <div class="shares-grid">
                        ${shareResults.readable_shares.map(share => `
                            <span class="share-badge readable">${safeDisplayValue(share)}</span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
            ${shareResults.writable_shares && shareResults.writable_shares.length > 0 ? `
                <div class="writable-shares">
                    <h6>✏️ Writable Shares (SECURITY RISK):</h6>
                    <div class="shares-grid">
                        ${shareResults.writable_shares.map(share => `
                            <span class="share-badge writable">${safeDisplayValue(share)}</span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
            <p><strong>Tool Used:</strong> ${safeDisplayValue(shareResults.tool_used || 'smbclient')}</p>
        </div>
    `;
}

function formatSMBUserEnumerationResults(userResults) {
    return `
        <div class="finding-section smb-user-enumeration">
            <h5>👥 User Enumeration Results</h5>
            <div class="user-enum-summary">
                <p><strong>Total Users Found:</strong> ${userResults.total_users || 0}</p>
                ${userResults.enumeration_methods && userResults.enumeration_methods.length > 0 ? `
                    <p><strong>Methods Used:</strong> ${userResults.enumeration_methods.join(', ')}</p>
                ` : ''}
            </div>
            ${userResults.users_found && userResults.users_found.length > 0 ? `
                <div class="enumerated-users">
                    <h6>🔍 Discovered Users:</h6>
                    <div class="users-grid">
                        ${userResults.users_found.map(user => `
                            <span class="user-badge discovered">${safeDisplayValue(user)}</span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function formatSMBPasswordAttackResults(passwordResults) {
    const hasCredentials = passwordResults.credentials_found && passwordResults.credentials_found.length > 0;

    return `
        <div class="finding-section smb-password-attacks ${hasCredentials ? 'critical' : 'secure'}">
            <h5>🔐 Password Attack Results</h5>
            <div class="password-attack-summary">
                <div class="attack-stats-grid">
                    <div class="attack-stat">
                        <span class="stat-number">${passwordResults.users_attacked || 0}</span>
                        <span class="stat-label">Users Attacked</span>
                    </div>
                    <div class="attack-stat ${hasCredentials ? 'critical' : 'secure'}">
                        <span class="stat-number">${passwordResults.successful_logins || 0}</span>
                        <span class="stat-label">Successful</span>
                    </div>
                    <div class="attack-stat">
                        <span class="stat-number">${safeDisplayValue(passwordResults.attack_method || 'Manual')}</span>
                        <span class="stat-label">Method</span>
                    </div>
                </div>
            </div>
            ${hasCredentials ? `
                <div class="credentials-found-alert">
                    <div class="alert-header">
                        <span class="alert-icon">🚨</span>
                        <span class="alert-title">CREDENTIALS DISCOVERED</span>
                    </div>
                    <div class="credentials-list">
                        ${passwordResults.credentials_found.map(cred => `
                            <div class="credential-item">
                                <strong>Username:</strong> <code>${safeDisplayValue(cred.username)}</code><br>
                                <strong>Password:</strong> <code>${safeDisplayValue(cred.password)}</code>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : `
                <div class="no-credentials">
                    <p>✅ No credentials found with common passwords.</p>
                </div>
            `}
        </div>
    `;
}




function showDeepSNMPScanButton(scanData) {
    console.log('🔍 SNMP Debug - showDeepSNMPScanButton called with:', scanData);

    // Check if we have nmap data
    const hasNmap = scanData.nmap_data && !scanData.nmap_data.error;

    console.log('🔍 SNMP Debug - Nmap available check result:', hasNmap);

    if (!hasNmap) {
        console.log('🔍 SNMP Debug - Deep SNMP scan not available - nmap not available or failed');
        return;
    }

    // Check if button already exists
    const existingBtn = document.getElementById('deepSNMPScanBtn');
    if (existingBtn) {
        existingBtn.remove();
    }

    const deepScanBtn = document.createElement('button');
    deepScanBtn.className = 'btn btn-warning deep-snmp-scan-btn';
    deepScanBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
        <span>Deep SNMP Scan (All Scripts + Brute Force)</span>
    `;
    deepScanBtn.id = 'deepSNMPScanBtn';
    deepScanBtn.onclick = () => startDeepSNMPScan(scanData);

    // Add to results actions
    const resultsActions = document.querySelector('.results-actions');
    if (resultsActions) {
        resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
        console.log('✅ Deep SNMP Scan button added successfully');
    }
}

// 3. Start Deep SNMP Scan Function
async function startDeepSNMPScan(previousScanData) {
    console.log('🎯 Starting deep SNMP scan for:', previousScanData);

    // Show warning dialog
    const userConfirmed = confirm(DEEP_SCAN_WARNINGS.snmp.message);

    if (!userConfirmed) {
        console.log('🚫 User cancelled deep SNMP scan');
        Utils.showNotification('Deep SNMP scan cancelled by user', 'info');
        return;
    }

    console.log('✅ User confirmed deep SNMP scan - proceeding...');

    const deepBtn = document.getElementById('deepSNMPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = true;
        deepBtn.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Running All SNMP Scripts + Brute Force...</span>
        `;
    }

    try {
        showDeepSNMPScanProgress(previousScanData);

        const payload = {
            targetIP: previousScanData.ip || previousScanData.targetIP,
            targetPort: previousScanData.port || previousScanData.targetPort,
            scanType: 'snmp',
            normal_scan_results: previousScanData
        };

        console.log('🚀 Starting deep SNMP scan with payload:', payload);

        const response = await fetch('/api/active-scan-aggressive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Deep SNMP scan failed');
        }

        const deepResults = await response.json();
        console.log('📥 Deep SNMP scan results:', deepResults);

        showDeepSNMPResults(deepResults, previousScanData);

    } catch (error) {
        console.error('❌ Deep SNMP scan error:', error);
        Utils.showNotification(`Deep SNMP scan failed: ${error.message}`, 'error');

        if (deepBtn) {
            deepBtn.disabled = false;
            deepBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
                <span>Deep SNMP Scan (All Scripts + Brute Force)</span>
            `;
        }
    }
}

// 4. Show Deep SNMP Scan Progress
function showDeepSNMPScanProgress(scanData) {
    const progressSection = document.getElementById('scanProgressSection');
    if (!progressSection) return;

    progressSection.classList.remove('hidden');

    const targetElement = document.getElementById('scanTarget');
    const serviceElement = document.getElementById('scanService');

    if (targetElement) {
        targetElement.textContent = `${scanData.ip || scanData.targetIP}:${scanData.port || scanData.targetPort}`;
    }

    if (serviceElement) {
        serviceElement.textContent = 'SNMP (Deep Scan - All Scripts + Brute Force)';
    }

    updateScanProgress(25, 'Loading comprehensive nmap SNMP script suite...');
    setTimeout(() => updateScanProgress(50, 'Running snmp-* scripts and community brute force...'), 1000);
    setTimeout(() => updateScanProgress(75, 'Enumerating system information and services...'), 2000);
    setTimeout(() => updateScanProgress(100, 'Deep SNMP scan completed'), 3000);
}

// 5. Show Deep SNMP Results
function showDeepSNMPResults(deepResults, originalResults) {
    console.log('🔍 Showing deep SNMP scan results');

    const progressSection = document.getElementById('scanProgressSection');
    if (progressSection) {
        progressSection.classList.add('hidden');
    }

    const resultsContent = document.getElementById('resultsContent');
    if (!resultsContent) return;

    // Add deep scan results indicator
    const deepIndicator = document.createElement('div');
    deepIndicator.className = 'deep-scan-results-indicator';
    deepIndicator.innerHTML = `
        <div class="deep-scan-banner">
            ⚡ Deep SNMP Scan Results (All Scripts + Brute Force)
            <span class="deep-scan-badge">Complete</span>
        </div>
    `;

    resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

    // Show brute force results FIRST (most important)
    if (deepResults.advanced_findings && deepResults.advanced_findings.brute_force_results) {
        const bruteResults = deepResults.advanced_findings.brute_force_results;

        if (bruteResults.success && bruteResults.communities_found && bruteResults.communities_found.length > 0) {
            const communitiesCard = document.createElement('div');
            communitiesCard.className = 'result-card communities-found-card critical-finding';
            communitiesCard.innerHTML = `
                <h4>🔓 SNMP Community Strings Discovered</h4>
                <div class="communities-alert">
                    <div class="alert-icon">🚨</div>
                    <div class="alert-text">
                        <strong>CRITICAL SECURITY ISSUE:</strong> SNMP community string brute force succeeded!
                    </div>
                </div>
                <div class="communities-list">
                    ${bruteResults.communities_found.map(community => `
                        <div class="community-item critical">
                            <div class="community-header">
                                <span class="community-type">📡 SNMP Community</span>
                                <span class="community-status">✅ Verified</span>
                            </div>
                            <div class="community-info">
                                <div class="community-field">
                                    <strong>Community String:</strong> 
                                    <code class="community-value">${safeDisplayValue(community)}</code>
                                </div>
                            </div>
                            <div class="community-impact">
                                <span class="impact-item">📊 Can read SNMP data</span>
                                <span class="impact-item">🔍 System enumeration possible</span>
                                <span class="impact-item">⚠️ Information disclosure risk</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
            resultsContent.appendChild(communitiesCard);
        } else if (bruteResults.brute_attempted) {
            const bruteCard = document.createElement('div');
            bruteCard.className = 'result-card brute-summary-card';
            bruteCard.innerHTML = `
                <h4>💥 SNMP Brute Force Summary</h4>
                <div class="brute-summary-grid">
                    <div class="summary-stat">
                        <div class="stat-number">${bruteResults.brute_attempted ? 'Yes' : 'No'}</div>
                        <div class="stat-label">Brute Force Attempted</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">${bruteResults.success ? 'Success' : 'Failed'}</div>
                        <div class="stat-label">Result</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-number">0</div>
                        <div class="stat-label">Communities Found</div>
                    </div>
                </div>
                <div class="brute-details">
                    <p><strong>Result:</strong> No community strings found with common values</p>
                    <p><em>💡 SNMP may use custom community strings or be properly secured</em></p>
                </div>
            `;
            resultsContent.appendChild(bruteCard);
        }
    }

    // Show Windows enumeration results
    if (deepResults.advanced_findings && deepResults.advanced_findings.windows_enumeration) {
        const windowsEnum = deepResults.advanced_findings.windows_enumeration;
        const windowsCard = document.createElement('div');
        windowsCard.className = 'result-card windows-enumeration-card';

        let windowsHTML = `<h4>🪟 Windows System Enumeration</h4><div class="windows-enumeration-content">`;

        if (windowsEnum.users && windowsEnum.users.length > 0) {
            windowsHTML += `
                <div class="enum-section">
                    <h5>👥 Users Discovered (${windowsEnum.users.length})</h5>
                    <div class="users-list">
                        ${windowsEnum.users.slice(0, 10).map(user => `
                            <span class="user-badge">${safeDisplayValue(user)}</span>
                        `).join('')}
                        ${windowsEnum.users.length > 10 ? `<span class="more-items">+${windowsEnum.users.length - 10} more</span>` : ''}
                    </div>
                </div>
            `;
        }

        if (windowsEnum.services && windowsEnum.services.length > 0) {
            windowsHTML += `
                <div class="enum-section">
                    <h5>⚙️ Services Discovered (${windowsEnum.services.length})</h5>
                    <div class="services-list">
                        ${windowsEnum.services.slice(0, 8).map(service => `
                            <div class="service-item">${safeDisplayValue(service)}</div>
                        `).join('')}
                        ${windowsEnum.services.length > 8 ? `<div class="more-items">+${windowsEnum.services.length - 8} more services</div>` : ''}
                    </div>
                </div>
            `;
        }

        if (windowsEnum.shares && windowsEnum.shares.length > 0) {
            windowsHTML += `
                <div class="enum-section">
                    <h5>📁 Shares Discovered (${windowsEnum.shares.length})</h5>
                    <div class="shares-list">
                        ${windowsEnum.shares.map(share => `
                            <span class="share-badge">${safeDisplayValue(share)}</span>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        if (windowsEnum.software && windowsEnum.software.length > 0) {
            windowsHTML += `
                <div class="enum-section">
                    <h5>💿 Software Discovered (${windowsEnum.software.length})</h5>
                    <div class="software-list">
                        ${windowsEnum.software.slice(0, 6).map(software => `
                            <div class="software-item">${safeDisplayValue(software)}</div>
                        `).join('')}
                        ${windowsEnum.software.length > 6 ? `<div class="more-items">+${windowsEnum.software.length - 6} more applications</div>` : ''}
                    </div>
                </div>
            `;
        }

        windowsHTML += '</div>';
        windowsCard.innerHTML = windowsHTML;
        resultsContent.appendChild(windowsCard);
    }

    // Show process enumeration
    if (deepResults.advanced_findings && deepResults.advanced_findings.process_enumeration) {
        const processEnum = deepResults.advanced_findings.process_enumeration;
        if (processEnum.running_processes && processEnum.running_processes.length > 0) {
            const processCard = document.createElement('div');
            processCard.className = 'result-card process-enumeration-card';
            processCard.innerHTML = `
                <h4>⚡ Process Enumeration</h4>
                <div class="process-enumeration-content">
                    <p><strong>Running Processes Found:</strong> ${processEnum.running_processes.length}</p>
                    <div class="processes-list">
                        ${processEnum.running_processes.slice(0, 10).map(process => `
                            <div class="process-item">${safeDisplayValue(process)}</div>
                        `).join('')}
                        ${processEnum.running_processes.length > 10 ? `<div class="more-items">+${processEnum.running_processes.length - 10} more processes</div>` : ''}
                    </div>
                </div>
            `;
            resultsContent.appendChild(processCard);
        }
    }

    // Show network enumeration
    if (deepResults.advanced_findings && deepResults.advanced_findings.network_enumeration) {
        const networkEnum = deepResults.advanced_findings.network_enumeration;
        if (networkEnum.network_connections && networkEnum.network_connections.length > 0) {
            const networkCard = document.createElement('div');
            networkCard.className = 'result-card network-enumeration-card';
            networkCard.innerHTML = `
                <h4>🌐 Network Connections</h4>
                <div class="network-enumeration-content">
                    <p><strong>Active Connections:</strong> ${networkEnum.network_connections.length}</p>
                    <div class="connections-list">
                        ${networkEnum.network_connections.map(connection => `
                            <div class="connection-item">${safeDisplayValue(connection)}</div>
                        `).join('')}
                    </div>
                </div>
            `;
            resultsContent.appendChild(networkCard);
        }
    }

    // Show raw nmap output
    if (deepResults.nmap_data && !deepResults.nmap_data.error) {
        const deepNmapCard = document.createElement('div');
        deepNmapCard.className = 'result-card deep-nmap-results';
        deepNmapCard.innerHTML = `
            <h4>📋 Full Deep SNMP Scan Output</h4>
            <div class="nmap-command-info">
                <strong>Command:</strong> ${deepResults.nmap_data.command_used || 'nmap -sU -p161 --script "snmp-*" --script-args snmp.version=all'}
            </div>
            <div class="nmap-raw-container">
                <pre class="nmap-raw-output">${deepResults.nmap_data.raw_output || 'No output available'}</pre>
            </div>
        `;
        resultsContent.appendChild(deepNmapCard);
    }

    // Update button
    const deepBtn = document.getElementById('deepSNMPScanBtn');
    if (deepBtn) {
        deepBtn.disabled = false;
        deepBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span>Deep Scan Completed ✓</span>
        `;
        deepBtn.onclick = null;
    }

    // Notification
    const bruteResults = deepResults.advanced_findings?.brute_force_results;
    const communitiesFound = bruteResults?.communities_found?.length || 0;
    const windowsData = deepResults.advanced_findings?.windows_enumeration;
    const hasEnumeration = windowsData && (windowsData.users?.length > 0 || windowsData.services?.length > 0);

    if (communitiesFound > 0) {
        Utils.showNotification(`🚨 CRITICAL: ${communitiesFound} SNMP community strings discovered!`, 'error');
    } else if (hasEnumeration) {
        Utils.showNotification('Deep SNMP scan completed with system enumeration', 'warning');
    } else {
        Utils.showNotification('Deep SNMP scan completed', 'success');
    }

    setTimeout(() => {
        resultsContent.scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

// 6. Format SNMP Advanced Findings
function formatSNMPAdvancedFindings(findings) {
    let html = '<div class="snmp-advanced-findings-content">';

    // System Information
    if (findings.system_info) {
        html += formatSNMPSystemInfo(findings.system_info);
    }

    // Network Interfaces
    if (findings.network_interfaces) {
        html += formatSNMPInterfaces(findings.network_interfaces);
    }

    // Brute Force Results (aggressive mode)
    if (findings.brute_force_results) {
        html += formatSNMPBruteForceResults(findings.brute_force_results);
    }

    // Windows Enumeration (aggressive mode)
    if (findings.windows_enumeration) {
        html += formatSNMPWindowsEnumeration(findings.windows_enumeration);
    }

    // Process Enumeration (aggressive mode)
    if (findings.process_enumeration) {
        html += formatSNMPProcessEnumeration(findings.process_enumeration);
    }

    // Network Enumeration (aggressive mode)
    if (findings.network_enumeration) {
        html += formatSNMPNetworkEnumeration(findings.network_enumeration);
    }

    html += '</div>';
    return html;
}

// 7. Helper Functions for SNMP Formatting
function formatSNMPSystemInfo(systemInfo) {
    return `
        <div class="finding-section snmp-system-info">
            <h5>🖥️ System Information</h5>
            <div class="system-info-grid">
                ${systemInfo.system_description ? `
                    <div class="system-info-item">
                        <strong>Description:</strong> ${safeDisplayValue(systemInfo.system_description)}
                    </div>
                ` : ''}
                ${systemInfo.system_name ? `
                    <div class="system-info-item">
                        <strong>System Name:</strong> ${safeDisplayValue(systemInfo.system_name)}
                    </div>
                ` : ''}
                ${systemInfo.system_contact ? `
                    <div class="system-info-item">
                        <strong>Contact:</strong> ${safeDisplayValue(systemInfo.system_contact)}
                    </div>
                ` : ''}
                ${systemInfo.system_location ? `
                    <div class="system-info-item">
                        <strong>Location:</strong> ${safeDisplayValue(systemInfo.system_location)}
                    </div>
                ` : ''}
                ${systemInfo.uptime ? `
                    <div class="system-info-item">
                        <strong>Uptime:</strong> ${safeDisplayValue(systemInfo.uptime)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function formatSNMPInterfaces(interfaces) {
    return `
        <div class="finding-section snmp-interfaces">
            <h5>🌐 Network Interfaces</h5>
            <div class="interfaces-summary">
                <div class="interface-stats">
                    <div class="interface-stat">
                        <span class="stat-number">${interfaces.total_interfaces || 0}</span>
                        <span class="stat-label">Total Interfaces</span>
                    </div>
                    <div class="interface-stat active">
                        <span class="stat-number">${interfaces.active_interfaces?.length || 0}</span>
                        <span class="stat-label">Active</span>
                    </div>
                </div>
            </div>
            ${interfaces.interface_details && interfaces.interface_details.length > 0 ? `
                <div class="interfaces-list">
                    ${interfaces.interface_details.slice(0, 8).map(iface => `
                        <div class="interface-item">${safeDisplayValue(iface)}</div>
                    `).join('')}
                    ${interfaces.interface_details.length > 8 ? `<div class="more-items">+${interfaces.interface_details.length - 8} more interfaces</div>` : ''}
                </div>
            ` : ''}
        </div>
    `;
}

function formatSNMPBruteForceResults(bruteResults) {
    const hasCommunitites = bruteResults.success && bruteResults.communities_found && bruteResults.communities_found.length > 0;

    return `
        <div class="finding-section snmp-brute-force ${hasCommunitites ? 'critical' : 'secure'}">
            <h5>🔐 SNMP Community String Brute Force</h5>
            <div class="brute-force-status ${hasCommunitites ? 'success' : 'failed'}">
                Status: ${hasCommunitites ? '🚨 COMMUNITY STRINGS FOUND' : '✅ NO WEAK STRINGS FOUND'}
            </div>
            ${hasCommunitites ? `
                <div class="communities-alert">
                    <div class="alert-header">
                        <span class="alert-icon">🚨</span>
                        <span class="alert-title">CRITICAL: SNMP Community Strings Discovered</span>
                    </div>
                    <div class="communities-list">
                        ${bruteResults.communities_found.map(community => `
                            <div class="community-item">
                                <strong>Community String:</strong> <code>${safeDisplayValue(community)}</code>
                            </div>
                        `).join('')}
                    </div>
                    <div class="security-impact">
                        <strong>Security Impact:</strong>
                        <ul>
                            <li>Full SNMP information access</li>
                            <li>System and network enumeration possible</li>
                            <li>Potential configuration disclosure</li>
                            <li>Network infrastructure mapping</li>
                        </ul>
                    </div>
                </div>
            ` : `
                <div class="no-communities">
                    <p>✅ Brute force attack did not find weak community strings.</p>
                    <p><em>SNMP may use custom community strings or be properly secured.</em></p>
                </div>
            `}
        </div>
    `;
}

function formatSNMPWindowsEnumeration(windowsEnum) {
    let html = `
        <div class="finding-section snmp-windows-enumeration">
            <h5>🪟 Windows System Enumeration</h5>
    `;

    if (windowsEnum.users && windowsEnum.users.length > 0) {
        html += `
            <div class="enum-subsection">
                <h6>👥 Users (${windowsEnum.users.length})</h6>
                <div class="users-grid">
                    ${windowsEnum.users.slice(0, 12).map(user => `
                        <span class="user-badge">${safeDisplayValue(user)}</span>
                    `).join('')}
                    ${windowsEnum.users.length > 12 ? `<span class="more-badge">+${windowsEnum.users.length - 12}</span>` : ''}
                </div>
            </div>
        `;
    }

    if (windowsEnum.services && windowsEnum.services.length > 0) {
        html += `
            <div class="enum-subsection">
                <h6>⚙️ Services (${windowsEnum.services.length})</h6>
                <div class="services-list">
                    ${windowsEnum.services.slice(0, 6).map(service => `
                        <div class="service-item">${safeDisplayValue(service)}</div>
                    `).join('')}
                    ${windowsEnum.services.length > 6 ? `<div class="more-items">... and ${windowsEnum.services.length - 6} more services</div>` : ''}
                </div>
            </div>
        `;
    }

    if (windowsEnum.shares && windowsEnum.shares.length > 0) {
        html += `
            <div class="enum-subsection">
                <h6>📁 Shares (${windowsEnum.shares.length})</h6>
                <div class="shares-grid">
                    ${windowsEnum.shares.map(share => `
                        <span class="share-badge">${safeDisplayValue(share)}</span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    if (windowsEnum.software && windowsEnum.software.length > 0) {
        html += `
            <div class="enum-subsection">
                <h6>💿 Software (${windowsEnum.software.length})</h6>
                <div class="software-list">
                    ${windowsEnum.software.slice(0, 5).map(software => `
                        <div class="software-item">${safeDisplayValue(software)}</div>
                    `).join('')}
                    ${windowsEnum.software.length > 5 ? `<div class="more-items">... and ${windowsEnum.software.length - 5} more applications</div>` : ''}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function formatSNMPProcessEnumeration(processEnum) {
    if (!processEnum.running_processes || processEnum.running_processes.length === 0) {
        return '';
    }

    return `
        <div class="finding-section snmp-process-enumeration">
            <h5>⚡ Running Processes</h5>
            <div class="process-summary">
                <p><strong>Processes Found:</strong> ${processEnum.running_processes.length}</p>
            </div>
            <div class="processes-list">
                ${processEnum.running_processes.slice(0, 10).map(process => `
                    <div class="process-item">${safeDisplayValue(process)}</div>
                `).join('')}
                ${processEnum.running_processes.length > 10 ? `<div class="more-items">... and ${processEnum.running_processes.length - 10} more processes</div>` : ''}
            </div>
        </div>
    `;
}

function formatSNMPNetworkEnumeration(networkEnum) {
    if (!networkEnum.network_connections || networkEnum.network_connections.length === 0) {
        return '';
    }

    return `
        <div class="finding-section snmp-network-enumeration">
            <h5>🌐 Network Connections</h5>
            <div class="network-summary">
                <p><strong>Active Connections:</strong> ${networkEnum.network_connections.length}</p>
            </div>
            <div class="connections-list">
                ${networkEnum.network_connections.map(connection => `
                    <div class="connection-item">${safeDisplayValue(connection)}</div>
                `).join('')}
            </div>
        </div>
    `;
}

// 8. SNMP Vulnerability Item Renderer
function renderSNMPVulnerabilityItem(vuln) {
    const severityClass = (vuln.severity || 'info').toLowerCase();
    const source = vuln.source || 'snmp_scanner';

    let badgeText = 'SCANNER';
    let badgeClass = 'scanner-badge';

    if (source.includes('nmap_nse') || vuln.detection_method?.includes('snmp-')) {
        badgeText = 'NMAP NSE';
        badgeClass = 'nmap-badge';
    } else if (source.includes('snmp_brute')) {
        badgeText = 'BRUTE FORCE';
        badgeClass = 'brute-badge';
    }

    return `
        <div class="vulnerability-item ${severityClass} snmp-vuln" data-source="${source}">
            <div class="vuln-header">
                <div class="vuln-id-section">
                    <span class="vuln-id">${safeDisplayValue(vuln.id || 'SNMP-FINDING')}</span>
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
                <div class="vuln-severity-section">
                    <span class="vuln-severity ${severityClass}">${safeDisplayValue(vuln.severity || 'Info')}</span>
                </div>
            </div>
            
            <div class="vuln-content">
                <div class="vuln-title">${safeDisplayValue(vuln.title || 'SNMP Security Finding')}</div>
                <div class="vuln-description">${safeDisplayValue(vuln.description || 'No description available')}</div>
                
                ${vuln.detection_method ? `
                    <div class="vuln-metadata">
                        <span class="metadata-item">
                            <strong>Detection Method:</strong> ${safeDisplayValue(vuln.detection_method)}
                        </span>
                    </div>
                ` : ''}
                
                ${vuln.recommendation ? `
                    <div class="vuln-recommendation">
                        <strong>💡 Recommendation:</strong> ${safeDisplayValue(vuln.recommendation)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function setupHTTPScanIntensity() {
    const intensitySelect = document.getElementById('httpScanIntensity');
    if (intensitySelect) {
        intensitySelect.addEventListener('change', function() {
            updateHTTPIntensityDescription();
        });
        updateHTTPIntensityDescription(); // Initialize description
    }
}

function updateHTTPIntensityDescription() {
    const intensity = document.getElementById('httpScanIntensity')?.value || 'normal';
    const descriptionDiv = document.getElementById('httpIntensityDescription');

    if (!descriptionDiv) return;

    const descriptions = {
        normal: '🟢 Safe scan - Basic web application security check, server analysis, and security headers examination. Won\'t trigger security alerts.',
        aggressive: '🔴 Deep scan - Comprehensive web vulnerability testing, directory enumeration, SQL injection testing, and extensive security analysis. May trigger security systems.'
    };

    descriptionDiv.textContent = descriptions[intensity];
    descriptionDiv.className = `intensity-description ${intensity}`;
}

document.addEventListener('DOMContentLoaded', function() {
    setupHTTPScanIntensity();
    setupHTTPSScanIntensity();

    // Make sure HTTP is properly handled in scan type detection
    const portInput = document.getElementById('targetPort');
    if (portInput) {
        portInput.addEventListener('change', updateScanTypeBasedOnPort);
        portInput.addEventListener('input', validatePortInput);
    }

    // Initialize all event listeners
    initializeActiveScan();
});;

const enhancedSSHCSS = `
.ssh-audit-results-card {
    border-left: 4px solid #3b82f6;
}

.ssh-audit-info {
    margin: 1rem 0;
    padding: 1rem;
    background: rgba(59, 130, 246, 0.05);
    border-radius: 8px;
}

.audit-command, .audit-method {
    margin: 0.5rem 0;
    font-size: 0.9rem;
}

.audit-command code {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.ssh-enhanced-analysis {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.ssh-section {
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid #059669;
}

.ssh-section h5 {
    color: #059669;
    margin: 0 0 1rem 0;
    font-size: 1rem;
}

.ssh-section h6 {
    color: #059669;
    margin: 0 0 0.75rem 0;
    font-size: 0.9rem;
    font-weight: 600;
}

.server-info-grid {
    display: grid;
    gap: 0.75rem;
}

.info-item {
    padding: 0.5rem;
    background: rgba(5, 150, 105, 0.05);
    border-radius: 4px;
}

.info-label {
    font-weight: 600;
    color: var(--text-primary);
    margin-right: 0.5rem;
}

.info-value {
    color: var(--text-secondary);
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.9rem;
}

.algorithm-summary {
    margin: 1rem 0;
}

.summary-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.stat-item {
    text-align: center;
    padding: 0.75rem;
    background: var(--bg-surface);
    border-radius: 8px;
    border: 2px solid var(--border-default);
}

.stat-item.total {
    border-color: #6b7280;
}

.stat-item.secure {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.05);
}

.stat-item.warning {
    border-color: #f59e0b;
    background: rgba(245, 158, 11, 0.05);
}

.stat-item.critical {
    border-color: #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.stat-number {
    display: block;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
}

.algorithm-category {
    margin: 1rem 0;
    padding: 0.75rem;
    background: rgba(5, 150, 105, 0.03);
    border-radius: 6px;
}

.algorithm-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.algorithm-item {
    padding: 0.75rem;
    border-radius: 6px;
    border-left: 4px solid var(--border-default);
}

.algorithm-item.fail,
.algorithm-item.critical {
    background: rgba(239, 68, 68, 0.05);
    border-left-color: #ef4444;
}

.algorithm-item.warn,
.algorithm-item.warning {
    background: rgba(245, 158, 11, 0.05);
    border-left-color: #f59e0b;
}

.algorithm-item.info,
.algorithm-item.secure {
    background: rgba(16, 185, 129, 0.05);
    border-left-color: #10b981;
}

.algorithm-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.algorithm-name {
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-weight: 600;
}

.algorithm-status {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
}

.algorithm-status.critical {
    background: #ef4444;
    color: white;
}

.algorithm-status.warning {
    background: #f59e0b;
    color: white;
}

.algorithm-status.secure {
    background: #10b981;
    color: white;
}

.algorithm-description {
    font-size: 0.85rem;
    color: var(--text-secondary);
}

.algorithm-more {
    padding: 0.5rem;
    text-align: center;
    font-style: italic;
    color: var(--text-secondary);
    background: rgba(107, 114, 128, 0.05);
    border-radius: 4px;
}

.issues-list, .recommendations-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.issue-item {
    padding: 0.75rem;
    border-radius: 6px;
    border-left: 4px solid var(--border-default);
}

.issue-item.critical {
    background: rgba(239, 68, 68, 0.05);
    border-left-color: #ef4444;
}

.issue-item.high {
    background: rgba(239, 68, 68, 0.05);
    border-left-color: #ef4444;
}

.issue-item.medium {
    background: rgba(245, 158, 11, 0.05);
    border-left-color: #f59e0b;
}

.issue-item.low {
    background: rgba(59, 130, 246, 0.05);
    border-left-color: #3b82f6;
}

.issue-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.issue-title {
    font-weight: 600;
    color: var(--text-primary);
}

.issue-severity {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    color: white;
}

.issue-severity.critical,
.issue-severity.high {
    background: #ef4444;
}

.issue-severity.medium {
    background: #f59e0b;
}

.issue-severity.low {
    background: #3b82f6;
}

.issue-description {
    margin: 0.5rem 0;
    color: var(--text-secondary);
}

.issue-recommendation {
    margin-top: 0.5rem;
    padding: 0.5rem;
    background: rgba(16, 185, 129, 0.05);
    border-radius: 4px;
    font-size: 0.9rem;
}

.issue-metadata {
    margin-top: 0.5rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
}

.issue-metadata code {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.recommendation-item {
    display: flex;
    gap: 0.75rem;
    padding: 0.75rem;
    background: rgba(59, 130, 246, 0.05);
    border-radius: 6px;
    border-left: 4px solid #3b82f6;
}

.rec-number {
    flex-shrink: 0;
    width: 1.5rem;
    height: 1.5rem;
    background: #3b82f6;
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 600;
}

.rec-text {
    color: var(--text-primary);
    line-height: 1.5;
}

.scripts-summary {
    background: rgba(107, 114, 128, 0.05);
    border-left-color: #6b7280;
}

.scripts-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.script-item {
    padding: 0.5rem;
    background: rgba(107, 114, 128, 0.05);
    border-radius: 4px;
    font-size: 0.9rem;
}

.ssh-security-score-section {
    margin: 1.5rem 0;
    padding: 1rem;
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(16, 185, 129, 0.1));
    border-radius: 8px;
    border: 1px solid rgba(59, 130, 246, 0.2);
}

.ssh-security-score-section h5 {
    color: #3b82f6;
    margin: 0 0 1rem 0;
}

.security-score-display {
    display: flex;
    align-items: center;
    gap: 1.5rem;
}

.security-score {
    display: flex;
    align-items: baseline;
    gap: 0.25rem;
    padding: 1rem;
    border-radius: 8px;
    min-width: 120px;
    justify-content: center;
}

.security-score.good {
    background: linear-gradient(135deg, #10b981, #059669);
    color: white;
}

.security-score.medium {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: white;
}

.security-score.poor {
    background: linear-gradient(135deg, #ef4444, #dc2626);
    color: white;
}

.score-number {
    font-size: 2rem;
    font-weight: 700;
}

.score-max {
    font-size: 1rem;
    opacity: 0.8;
}

.security-score-description {
    flex: 1;
    color: var(--text-primary);
    font-weight: 500;
}

.ssh-audit-formatted-output {
    margin: 1.5rem 0;
}

.ssh-audit-formatted-output h5 {
    color: #3b82f6;
    margin: 0 0 1rem 0;
}

.ssh-audit-content {
    background: var(--bg-surface);
    border-radius: 6px;
    border: 1px solid var(--border-default);
}

.ssh-audit-display {
    margin: 0;
    padding: 1rem;
    white-space: pre-wrap;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.85rem;
    line-height: 1.4;
    max-height: 400px;
    overflow-y: auto;
    color: var(--text-primary);
}

.ssh-audit-raw-output {
    margin: 1rem 0;
}

.ssh-audit-raw-output summary {
    cursor: pointer;
    padding: 0.75rem;
    background: rgba(107, 114, 128, 0.1);
    border-radius: 6px;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    color: var(--text-primary);
}

.ssh-audit-raw-output summary:hover {
    background: rgba(107, 114, 128, 0.15);
}

.summary-icon {
    font-size: 1rem;
}

.summary-text {
    flex: 1;
}

.ssh-raw-container {
    margin-top: 0.5rem;
    background: var(--bg-surface);
    border-radius: 6px;
    border: 1px solid var(--border-default);
}

.ssh-raw-output {
    margin: 0;
    padding: 1rem;
    white-space: pre-wrap;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.8rem;
    line-height: 1.3;
    max-height: 300px;
    overflow-y: auto;
    color: var(--text-secondary);
}

.ssh-audit-basic-card {
    border-left: 4px solid #6b7280;
}

.ssh-audit-basic {
    padding: 1rem;
}

.ssh-audit-status {
    margin-bottom: 1rem;
}

.ssh-audit-status p {
    margin: 0.5rem 0;
}

.ssh-audit-status code {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.ssh-basic-info {
    padding: 1rem;
    background: rgba(107, 114, 128, 0.05);
    border-radius: 6px;
}

.ssh-basic-info p {
    margin: 0.5rem 0;
}

.ssh-audit-error {
    border-left: 4px solid #f59e0b;
}

.error-content {
    display: flex;
    gap: 1rem;
    padding: 1rem;
}

.error-icon {
    font-size: 2rem;
    color: #f59e0b;
}

.error-details {
    flex: 1;
}

.error-message {
    background: rgba(245, 158, 11, 0.1);
    padding: 0.75rem;
    border-radius: 6px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.9rem;
    margin: 0.5rem 0;
}

.error-note {
    font-style: italic;
    color: var(--text-secondary);
    font-size: 0.9rem;
}

/* Responsive design */
@media (max-width: 768px) {
    .summary-stats {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .security-score-display {
        flex-direction: column;
        gap: 1rem;
    }
    
    .algorithm-header,
    .issue-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
}
`;

// Inject the enhanced SSH CSS if it doesn't exist
if (!document.getElementById('enhanced-ssh-css')) {
    const style = document.createElement('style');
    style.id = 'enhanced-ssh-css';
    style.textContent = enhancedSSHCSS;
    document.head.appendChild(style);
}

const snmpScannerCSS = `
/* SNMP Scanner Specific Styles */
.snmp-advanced-findings-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.system-info-grid {
    display: grid;
    gap: 0.75rem;
    margin: 1rem 0;
}

.system-info-item {
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid #3b82f6;
}

.system-info-item strong {
    color: #3b82f6;
    display: block;
    margin-bottom: 0.25rem;
    font-size: 0.9rem;
}

.interfaces-summary {
    margin: 1rem 0;
}

.interface-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.interface-stat {
    text-align: center;
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 2px solid var(--border-default);
}

.interface-stat.active {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.1);
}

.interfaces-list, .processes-list, .connections-list, .services-list, .software-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin: 1rem 0;
    max-height: 300px;
    overflow-y: auto;
}

.interface-item, .process-item, .connection-item, .service-item, .software-item {
    padding: 0.5rem;
    background: var(--bg-card);
    border-radius: 6px;
    border-left: 3px solid #6b7280;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.85rem;
}

.communities-found-card {
    border: 2px solid #ef4444 !important;
    background: rgba(239, 68, 68, 0.05) !important;
}

.communities-alert {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
    padding: 1rem;
    background: rgba(239, 68, 68, 0.1);
    border-radius: 8px;
}

.communities-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.community-item {
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.community-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.community-type {
    font-weight: 600;
    color: #ef4444;
}

.community-status {
    font-weight: 600;
    color: #10b981;
}

.community-info {
    margin: 0.5rem 0;
}

.community-field {
    margin: 0.25rem 0;
}

.community-value {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-weight: 600;
    color: #ef4444;
}

.community-impact {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.impact-item {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.windows-enumeration-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.enum-section {
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid #8b5cf6;
}

.enum-section h5 {
    color: #8b5cf6;
    margin: 0 0 1rem 0;
    font-size: 1rem;
}

.users-list, .shares-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.user-badge, .share-badge {
    background: rgba(139, 92, 246, 0.1);
    color: #8b5cf6;
    border: 1px solid #8b5cf6;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.users-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.shares-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.more-items, .more-badge {
    background: rgba(107, 114, 128, 0.1);
    color: #6b7280;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    font-style: italic;
}

.enum-subsection {
    margin: 1rem 0;
    padding: 0.75rem;
    background: rgba(139, 92, 246, 0.05);
    border-radius: 6px;
}

.enum-subsection h6 {
    color: #8b5cf6;
    margin: 0 0 0.75rem 0;
    font-size: 0.9rem;
    font-weight: 600;
}

.process-summary, .network-summary {
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 6px;
    margin: 1rem 0;
}

.brute-force-status.success {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 0.75rem;
    margin: 1rem 0;
    font-weight: 600;
}

.brute-force-status.failed {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid #10b981;
    border-radius: 6px;
    padding: 0.75rem;
    margin: 1rem 0;
    font-weight: 600;
}

.no-communities {
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    margin: 1rem 0;
}

.security-impact ul {
    margin: 0.5rem 0;
    padding-left: 1.5rem;
}

.security-impact li {
    margin: 0.25rem 0;
    color: #ef4444;
}

.snmp-vuln .nmap-badge {
    background: #3b82f6;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.snmp-vuln .brute-badge {
    background: #ef4444;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.snmp-vuln .scanner-badge {
    background: #6b7280;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.stat-number {
    display: block;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
}

.deep-snmp-scan-btn {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    border: none;
    color: white;
    font-weight: 600;
    transition: all 0.3s ease;
}

.deep-snmp-scan-btn:hover {
    background: linear-gradient(135deg, #d97706, #b45309);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
}

.deep-snmp-scan-btn:disabled {
    opacity: 0.6;
    transform: none;
    box-shadow: none;
}

.deep-snmp-scan-btn svg {
    width: 1rem;
    height: 1rem;
    margin-right: 0.5rem;
}

.spinning {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
`;

// Inject the SNMP CSS
if (!document.getElementById('snmp-scanner-css')) {
    const style = document.createElement('style');
    style.id = 'snmp-scanner-css';
    style.textContent = snmpScannerCSS;
    document.head.appendChild(style);
}



const httpsCSS = `
.https-scan-info {
    margin: 1rem 0;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
}

.scan-mode-indicator {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.scan-mode-indicator.normal .mode-badge {
    background: #10b981;
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.scan-mode-indicator.aggressive .mode-badge {
    background: #ef4444;
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.mode-description {
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.certificate-info-grid {
    display: grid;
    gap: 1rem;
    margin: 1rem 0;
}

.cert-info-item {
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid var(--border-default);
}

.cert-info-item.valid {
    border-left-color: #10b981;
    background: rgba(16, 185, 129, 0.05);
}

.cert-info-item.invalid,
.cert-info-item.expired {
    border-left-color: #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.cert-info-item.warning {
    border-left-color: #f59e0b;
    background: rgba(245, 158, 11, 0.05);
}

.cert-label {
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
}

.cert-value {
    color: var(--text-secondary);
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.9rem;
}

.https-advanced-findings-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.ssl-security-analysis,
.web-security-analysis {
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid #3b82f6;
}

.ssl-finding-item,
.web-finding-item {
    margin: 1rem 0;
    padding: 0.75rem;
    background: rgba(59, 130, 246, 0.05);
    border-radius: 6px;
}

.ssl-cert-details,
.ssl-cipher-details,
.security-headers-details,
.server-info-details,
.directories-details,
.backup-files-details {
    margin-top: 0.5rem;
    padding: 0.5rem;
    background: var(--bg-surface);
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.85rem;
    white-space: pre-wrap;
    max-height: 200px;
    overflow-y: auto;
}

.intensity-description {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
}

.intensity-description.normal {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.intensity-description.aggressive {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.https-vuln .ssl-badge {
    background: #3b82f6;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.https-vuln .web-badge {
    background: #8b5cf6;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.https-vuln .cert-badge {
    background: #059669;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}
`;

// Inject HTTPS CSS
if (!document.getElementById('https-css')) {
    const style = document.createElement('style');
    style.id = 'https-css';
    style.textContent = httpsCSS;
    document.head.appendChild(style);
}

if (typeof DEEP_SCAN_WARNINGS === 'undefined') {
    window.DEEP_SCAN_WARNINGS = {};
}


// ADD this CSS section to the end of your active-scan.js file (before the final console.log statements)

const smbNmapCSS = `
.os-discovery-status.detected {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid #10b981;
    border-radius: 6px;
    padding: 0.5rem;
    margin: 0.5rem 0;
}

.os-discovery-status.not-detected {
    background: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
    border: 1px solid #f59e0b;
    border-radius: 6px;
    padding: 0.5rem;
    margin: 0.5rem 0;
}

.os-detail {
    padding: 0.25rem 0;
    border-bottom: 1px solid var(--border-default);
}

.security-mode-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.security-setting {
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 2px solid var(--border-default);
    text-align: center;
}

.security-setting.secure {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.1);
}

.security-setting.insecure {
    border-color: #ef4444;
    background: rgba(239, 68, 68, 0.1);
}

.setting-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
}

.setting-value {
    font-weight: 600;
    color: var(--text-primary);
}

.security-warning {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 0.75rem;
    margin: 1rem 0;
    color: #ef4444;
    font-weight: 600;
}

.vuln-findings-summary, .brute-force-status {
    margin: 1rem 0;
}

.vuln-finding-item, .enum-finding-item {
    margin: 0.5rem 0;
    padding: 0.75rem;
    border-radius: 8px;
    border-left: 4px solid var(--border-default);
}

.vuln-finding-item.critical {
    border-left-color: #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.vuln-finding-item.vulnerable {
    border-left-color: #f59e0b;
    background: rgba(245, 158, 11, 0.05);
}

.vuln-finding-item.secure {
    border-left-color: #10b981;
    background: rgba(16, 185, 129, 0.05);
}

.vuln-script-header, .enum-script-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.vuln-status.vulnerable {
    color: #ef4444;
    font-weight: 600;
}

.vuln-status.secure {
    color: #10b981;
    font-weight: 600;
}

.brute-credentials-alert {
    background: rgba(239, 68, 68, 0.1);
    border: 2px solid #ef4444;
    border-radius: 8px;
    padding: 1rem;
    margin: 1rem 0;
}

.brute-force-status.success {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 0.5rem;
}

.brute-force-status.failed {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid #10b981;
    border-radius: 6px;
    padding: 0.5rem;
}

.security-impact ul {
    margin: 0.5rem 0;
    padding-left: 1.5rem;
}

.security-impact li {
    margin: 0.25rem 0;
    color: #ef4444;
}

.share-badge.accessible, .share-badge.readable {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
    border: 1px solid #10b981;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 0.25rem;
    display: inline-block;
}

.share-badge.found {
    background: rgba(59, 130, 246, 0.2);
    color: #3b82f6;
    border: 1px solid #3b82f6;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 0.25rem;
    display: inline-block;
}

.shares-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.share-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.share-stat {
    text-align: center;
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 2px solid var(--border-default);
}

.share-stat.accessible {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.1);
}

.share-stat.warning {
    border-color: #f59e0b;
    background: rgba(245, 158, 11, 0.1);
}

.share-stat.secure {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.1);
}

.stat-number {
    display: block;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
}

.brute-summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.summary-stat {
    text-align: center;
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 2px solid var(--border-default);
}

.brute-details {
    margin: 1rem 0;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
}

.credentials-found-card {
    border: 2px solid #ef4444 !important;
    background: rgba(239, 68, 68, 0.05) !important;
}

.credentials-alert {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
    padding: 1rem;
    background: rgba(239, 68, 68, 0.1);
    border-radius: 8px;
}

.alert-icon {
    font-size: 2rem;
}

.alert-text strong {
    color: #ef4444;
    font-weight: 700;
}

.credential-item {
    margin: 0.5rem 0;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.credential-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.credential-type {
    font-weight: 600;
    color: #ef4444;
}

.credential-status {
    font-weight: 600;
    color: #10b981;
}

.credential-info {
    margin: 0.5rem 0;
}

.credential-field {
    margin: 0.25rem 0;
}

.credential-value {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-weight: 600;
}

.credential-impact {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.impact-item {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}
`;

// Inject the CSS for SMB nmap results
if (!document.getElementById('smb-nmap-css')) {
    const style = document.createElement('style');
    style.id = 'smb-nmap-css';
    style.textContent = smbNmapCSS;
    document.head.appendChild(style);
}


const smtpAdvancedCSS = `
.smtp-commands-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.smtp-command-item {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.smtp-command-item.safe {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.smtp-command-item.dangerous {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.enum-methods {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.method-badge {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.valid-users-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.5rem;
}

.user-badge {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
    background: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.3);
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.command-status {
    margin-right: 1rem;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
}

.command-status.enabled {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
}

.command-status.disabled {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.relay-status.critical {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 6px;
    padding: 0.5rem;
}

.relay-status.good {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 6px;
    padding: 0.5rem;
}

.confidence-critical { color: #ef4444; font-weight: 700; }
.confidence-warning { color: #f59e0b; font-weight: 700; }
.confidence-good { color: #10b981; font-weight: 700; }

.timing-item {
    padding: 0.5rem;
    margin: 0.25rem 0;
    border-radius: 4px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.85rem;
}

.timing-item.different {
    background: rgba(245, 158, 11, 0.1);
    border-left: 3px solid #f59e0b;
}

.timing-item.normal {
    background: rgba(16, 185, 129, 0.1);
    border-left: 3px solid #10b981;
}

.info-leakage-list {
    margin: 0.5rem 0;
    padding-left: 1rem;
}

.info-leakage-list li {
    margin: 0.25rem 0;
    color: var(--text-secondary);
    font-size: 0.85rem;
}

.banner-analysis-subsection,
.vrfy-testing-subsection,
.expn-testing-subsection,
.relay-results-subsection,
.extensive-relay-subsection,
.timing-differences-subsection {
    margin-top: 1rem;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 3px solid #059669;
}

.banner-analysis-subsection h6,
.vrfy-testing-subsection h6,
.expn-testing-subsection h6,
.relay-results-subsection h6,
.extensive-relay-subsection h6,
.timing-differences-subsection h6 {
    color: #059669;
    margin: 0 0 0.75rem 0;
    font-size: 0.9rem;
    font-weight: 600;
}
`;

// Inject the CSS
if (!document.getElementById('smtp-advanced-css')) {
    const style = document.createElement('style');
    style.id = 'smtp-advanced-css';
    style.textContent = smtpAdvancedCSS;
    document.head.appendChild(style);
}


document.addEventListener('DOMContentLoaded', function() {
    addSMTPScriptHighlighting();
});


const originalShowNotification = Utils.showNotification;
Utils.showNotification = function(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Create toast notification with enhanced styling for warnings
    const toast = document.createElement('div');
    toast.className = `notification ${type}`;

    let backgroundColor;
    let icon = '';

    switch(type) {
        case 'success':
            backgroundColor = 'linear-gradient(135deg, #10b981, #059669)';
            icon = '✅ ';
            break;
        case 'error':
            backgroundColor = 'linear-gradient(135deg, #ef4444, #dc2626)';
            icon = '❌ ';
            break;
        case 'warning':
            backgroundColor = 'linear-gradient(135deg, #f59e0b, #d97706)';
            icon = '⚠️ ';
            break;
        case 'info':
            backgroundColor = 'linear-gradient(135deg, #3b82f6, #2563eb)';
            icon = 'ℹ️ ';
            break;
        default:
            backgroundColor = 'linear-gradient(135deg, #3b82f6, #2563eb)';
            icon = 'ℹ️ ';
    }

    toast.style.cssText = `
        position: fixed; top: 2rem; right: 2rem; 
        background: ${backgroundColor};
        color: white; padding: 1rem 1.5rem; border-radius: 12px; 
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        z-index: 1001; font-weight: 600; animation: slideIn 0.4s ease;
        max-width: 350px; font-family: 'Inter', sans-serif;
        border: 1px solid rgba(255, 255, 255, 0.2);
    `;
    toast.textContent = icon + message;
    document.body.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, 300);
        }
    }, type === 'error' ? 6000 : 4000); // Error messages stay longer
};

// Add slideOut animation
if (!document.getElementById('slideOutAnimation')) {
    const style = document.createElement('style');
    style.id = 'slideOutAnimation';
    style.textContent += `
        @keyframes slideOut {
            from { opacity: 1; transform: translateX(0); }
            to { opacity: 0; transform: translateX(100%); }
        }
    `;
    document.head.appendChild(style);
}

const smbAdditionalCSS = `
.smb-version-badge, .share-badge, .user-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 0.25rem;
}

.smb-version-badge {
    background: #8b5cf6;
    color: white;
}

.share-badge.accessible, .share-badge.readable {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
    border: 1px solid #10b981;
}

.share-badge.writable {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border: 1px solid #ef4444;
}

.user-badge.discovered, .user-badge.enumerated {
    background: rgba(245, 158, 11, 0.2);
    color: #f59e0b;
    border: 1px solid #f59e0b;
}

.shares-grid, .users-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.eternalblue-critical-alert, .credentials-found-alert {
    background: rgba(239, 68, 68, 0.1);
    border: 2px solid #ef4444;
    border-radius: 8px;
    padding: 1rem;
    margin: 1rem 0;
}

.alert-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1rem;
    font-weight: 700;
    color: #ef4444;
}

.plan-stats, .share-stats-grid, .attack-stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.plan-stat, .share-stat, .attack-stat {
    text-align: center;
    padding: 0.75rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 2px solid var(--border-default);
}

.attack-stat.critical, .plan-stat.risk-high {
    border-color: #ef4444;
    background: rgba(239, 68, 68, 0.1);
}

.reasoning-list {
    list-style: none;
    padding: 0;
}

.reasoning-list li {
    padding: 0.5rem;
    margin: 0.25rem 0;
    background: var(--bg-card);
    border-radius: 4px;
    border-left: 3px solid #8b5cf6;
}
`;


if (!document.getElementById('smb-additional-css')) {
    const style = document.createElement('style');
    style.id = 'smb-additional-css';
    style.textContent = smbAdditionalCSS;
    document.head.appendChild(style);
}

const httpCSS = `
/* HTTP Scanner Specific Styles */
.http-scan-info {
    margin: 1rem 0;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
}

.scan-mode-indicator {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.scan-mode-indicator.normal .mode-badge {
    background: #10b981;
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.scan-mode-indicator.aggressive .mode-badge {
    background: #ef4444;
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.mode-description {
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.http-web-analysis-container,
.http-server-analysis-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.web-section,
.server-section {
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border-left: 4px solid #3b82f6;
}

.web-section h5,
.server-section h5 {
    color: #3b82f6;
    margin: 0 0 1rem 0;
    font-size: 1rem;
}

.security-headers-analysis {
    margin: 1rem 0;
}

.headers-present,
.headers-missing {
    margin: 0.5rem 0;
}

.headers-present ul,
.headers-missing ul {
    margin: 0.5rem 0;
    padding-left: 1.5rem;
}

.directories-list,
.backup-files-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin: 1rem 0;
}

.directory-item,
.backup-file-item {
    padding: 0.5rem;
    background: rgba(59, 130, 246, 0.1);
    border-radius: 6px;
    border-left: 3px solid #3b82f6;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
    font-size: 0.85rem;
}

.backup-file-item.critical {
    background: rgba(239, 68, 68, 0.1);
    border-left-color: #ef4444;
    color: #ef4444;
}

.vulnerability-tests-container {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.vuln-test-item {
    padding: 0.75rem;
    border-radius: 6px;
    border-left: 4px solid var(--border-default);
}

.vuln-test-item.vulnerable {
    background: rgba(239, 68, 68, 0.1);
    border-left-color: #ef4444;
}

.vuln-test-item.secure {
    background: rgba(16, 185, 129, 0.1);
    border-left-color: #10b981;
}

.test-details {
    margin-top: 0.5rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
}

.server-info-grid {
    display: grid;
    gap: 0.75rem;
    margin: 1rem 0;
}

.server-info-item {
    padding: 0.5rem;
    background: rgba(59, 130, 246, 0.05);
    border-radius: 4px;
}

.methods-analysis-container {
    margin: 1rem 0;
}

.methods-section {
    margin: 0.75rem 0;
}

.methods-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
}

.method-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
}

.method-badge.safe {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
    border: 1px solid #10b981;
}

.method-badge.dangerous {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border: 1px solid #ef4444;
}

.auth-tests-container {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.auth-test-item {
    padding: 0.5rem;
    background: var(--bg-surface);
    border-radius: 4px;
}

.http-vuln .nmap-badge {
    background: #3b82f6;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.http-vuln .web-badge {
    background: #8b5cf6;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.http-vuln .server-badge {
    background: #059669;
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
}

.deep-http-scan-btn {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    border: none;
    color: white;
    font-weight: 600;
    transition: all 0.3s ease;
}

.deep-http-scan-btn:hover {
    background: linear-gradient(135deg, #d97706, #b45309);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
}

.deep-http-scan-btn:disabled {
    opacity: 0.6;
    transform: none;
    box-shadow: none;
}

.deep-http-scan-btn svg {
    width: 1rem;
    height: 1rem;
    margin-right: 0.5rem;
}
`;

// Inject the HTTP CSS
if (!document.getElementById('http-scanner-css')) {
    const style = document.createElement('style');
    style.id = 'http-scanner-css';
    style.textContent = httpCSS;
    document.head.appendChild(style);
}



window.formatSMTPAdvancedFindings = formatSMTPAdvancedFindings;


window.showDeepSSHScanButton = showDeepSSHScanButton;
window.startDeepSSHScan = startDeepSSHScan;
window.showDeepSSHScanProgress = showDeepSSHScanProgress;
window.showDeepSSHResults = showDeepSSHResults;
window.addSSHAuditResultsDisplay = addSSHAuditResultsDisplay;
window.renderSSHVulnerabilityItem = renderSSHVulnerabilityItem;
window.formatSSHServiceInfo = formatSSHServiceInfo;
window.renderSSHAnalysisCard = renderSSHAnalysisCard;
window.getScoreClass = getScoreClass;
window.getScoreDescription = getScoreDescription;


window.createVulnerabilityFromAlgorithm = createVulnerabilityFromAlgorithm;
window.getAlgorithmRecommendation = getAlgorithmRecommendation;
window.getAlgorithmSeverity = getAlgorithmSeverity;
window.renderSSHAuditError = renderSSHAuditError;
window.parseEnhancedSSHAuditOutput = parseEnhancedSSHAuditOutput;
window.parseSSHAuditFromJSON = parseSSHAuditFromJSON;
window.renderEnhancedSSHAnalysis = renderEnhancedSSHAnalysis;
window.renderSSHServerInfo = renderSSHServerInfo;
window.renderEnhancedAlgorithmAnalysis = renderEnhancedAlgorithmAnalysis;
window.renderSSHSecurityIssues = renderSSHSecurityIssues;
window.renderSSHRecommendations = renderSSHRecommendations;
window.renderSSHSecuritySummary = renderSSHSecuritySummary;

window.parseSSHAuditOutput = parseSSHAuditOutput;
window.renderSSHAuditResults = renderSSHAuditResults;
window.addEnhancedSSHAuditDisplay = addEnhancedSSHAuditDisplay;

window.addEnhancedSSHAuditDisplay = addEnhancedSSHAuditDisplay;
window.renderEnhancedSSHAnalysisFixed = renderEnhancedSSHAnalysisFixed;
window.renderSSHServerInfoFixed = renderSSHServerInfoFixed;
window.renderSSHAlgorithmAnalysisFixed = renderSSHAlgorithmAnalysisFixed;
window.renderSSHVulnerabilitiesFixed = renderSSHVulnerabilitiesFixed;
window.renderSSHRecommendationsFixed = renderSSHRecommendationsFixed;
window.renderSSHScriptsSummary = renderSSHScriptsSummary;
window.renderSSHAuditError = renderSSHAuditError;
window.getScoreClass = getScoreClass;
window.getScoreDescription = getScoreDescription;

window.showDeepSMTPScanButton = showDeepSMTPScanButton;
window.startDeepSMTPScan = startDeepSMTPScan;
window.showDeepSMTPScanProgress = showDeepSMTPScanProgress;
window.showDeepSMTPResults = showDeepSMTPResults;
window.formatSMTPDNSAnalysis = formatSMTPDNSAnalysis;
window.renderSMTPVulnerabilityItem = renderSMTPVulnerabilityItem;


window.showDeepSMBScanButton = showDeepSMBScanButton;
window.startDeepSMBScan = startDeepSMBScan;
window.showDeepSMBScanProgress = showDeepSMBScanProgress;
window.showDeepSMBResults = showDeepSMBResults;
window.formatSMBServiceInfo = formatSMBServiceInfo;
window.renderSMBVulnerabilityItem = renderSMBVulnerabilityItem;


window.formatSMBProtocolAnalysis = formatSMBProtocolAnalysis;
window.formatSMBAdvancedFindings = formatSMBAdvancedFindings;
window.formatSMBDeepScanPlan = formatSMBDeepScanPlan;
window.formatSMBNullSessionResults = formatSMBNullSessionResults;
window.formatSMBEternalBlueResults = formatSMBEternalBlueResults;
window.formatSMBShareAnalysisResults = formatSMBShareAnalysisResults;
window.formatSMBUserEnumerationResults = formatSMBUserEnumerationResults;
window.formatSMBPasswordAttackResults = formatSMBPasswordAttackResults;

window.showDeepSNMPScanButton = showDeepSNMPScanButton;
window.startDeepSNMPScan = startDeepSNMPScan;
window.showDeepSNMPScanProgress = showDeepSNMPScanProgress;
window.showDeepSNMPResults = showDeepSNMPResults;
window.formatSNMPAdvancedFindings = formatSNMPAdvancedFindings;
window.renderSNMPVulnerabilityItem = renderSNMPVulnerabilityItem;


window.formatSNMPSystemInfo = formatSNMPSystemInfo;
window.formatSNMPInterfaces = formatSNMPInterfaces;
window.formatSNMPBruteForceResults = formatSNMPBruteForceResults;
window.formatSNMPWindowsEnumeration = formatSNMPWindowsEnumeration;
window.formatSNMPProcessEnumeration = formatSNMPProcessEnumeration;
window.formatSNMPNetworkEnumeration = formatSNMPNetworkEnumeration;

window.formatSNMPProtocolAnalysis = formatSNMPProtocolAnalysis;
window.hasValidCVEData = hasValidCVEData;
window.renderCVEAnalysisCard = renderCVEAnalysisCard;



window.showDeepHTTPSScanButton = showDeepHTTPSScanButton;
window.startDeepHTTPSScan = startDeepHTTPSScan;
window.showDeepHTTPSScanProgress = showDeepHTTPSScanProgress;
window.showDeepHTTPSResults = showDeepHTTPSResults;
window.formatSSLAnalysis = formatSSLAnalysis;
window.formatWebAnalysis = formatWebAnalysis;
window.formatSecurityHeaders = formatSecurityHeaders;
window.renderHTTPSVulnerabilityItem = renderHTTPSVulnerabilityItem;
window.setupHTTPSScanIntensity = setupHTTPSScanIntensity;
window.updateHTTPSIntensityDescription = updateHTTPSIntensityDescription;

window.extractCertificateInfo = extractCertificateInfo;
window.formatCertificateAnalysis = formatCertificateAnalysis;
window.formatHTTPSAdvancedFindings = formatHTTPSAdvancedFindings;
window.formatSSLSecurityAnalysis = formatSSLSecurityAnalysis;
window.formatWebSecurityAnalysis = formatWebSecurityAnalysis;


window.showDeepHTTPScanButton = showDeepHTTPScanButton;
window.startDeepHTTPScan = startDeepHTTPScan;
window.showDeepHTTPScanProgress = showDeepHTTPScanProgress;
window.showDeepHTTPResults = showDeepHTTPResults;
window.formatHTTPWebAnalysis = formatHTTPWebAnalysis;
window.formatHTTPServerAnalysis = formatHTTPServerAnalysis;
window.renderHTTPVulnerabilityItem = renderHTTPVulnerabilityItem;
window.formatHTTPServiceInfo = formatHTTPServiceInfo;
window.formatHTTPAdvancedFindings = formatHTTPAdvancedFindings;


console.log('Active Scan JavaScript loaded successfully - NO SHODAN');
console.log('Debug functions available in window.debugActiveScan');
console.log('Available debug commands:');
console.log('- window.debugActiveScan.testSessionStorage()');
console.log('- window.debugActiveScan.simulateImport()');
console.log('- window.debugActiveScan.checkSessionStorage()');
console.log('- window.debugActiveScan.testFormSubmission()');
console.log('- window.debugActiveScan.checkFormElements()');

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupScanForm);
} else {
    setupScanForm();
}