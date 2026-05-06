class FTPScanner extends BaseScanner {
    constructor() {
        super('ftp');
        this.setupDeepScanWarnings();
        this.injectCSS();
    }

    setupDeepScanWarnings() {
        this.deepScanWarnings = {
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
        };
    }

    showDeepScanButton(scanData) {
        if (!this.hasValidNmapData(scanData)) {
            console.log('Deep FTP scan not available - nmap not detected');
            return;
        }

        const existingBtn = document.getElementById('deepFTPScanBtn');
        if (existingBtn) existingBtn.remove();

        const deepScanBtn = document.createElement('button');
        deepScanBtn.className = 'btn btn-warning deep-ftp-scan-btn';
        deepScanBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
            <span>Deep FTP Scan (All Scripts)</span>
        `;
        deepScanBtn.id = 'deepFTPScanBtn';
        deepScanBtn.onclick = () => this.startDeepScan(scanData);

        const resultsActions = document.querySelector('.results-actions');
        if (resultsActions) {
            resultsActions.insertBefore(deepScanBtn, resultsActions.firstChild);
            console.log('✅ Deep FTP Scan button added');
        }
    }

    async startDeepScan(scanData) {
        const userConfirmed = confirm(this.deepScanWarnings.message);
        if (!userConfirmed) {
            window.ActiveScanUtils.showNotification('Deep FTP scan cancelled by user', 'info');
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
            this.showDeepScanProgress(scanData);

            const payload = {
                targetIP: scanData.ip || scanData.targetIP,
                targetPort: scanData.port || scanData.targetPort,
                scanType: 'ftp',
                enableCveCheck: true,
                deepScan: true
            };

            console.log('🚀 Starting deep FTP scan with payload:', payload);

            const response = await fetch('/api/active-scan-aggressive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Deep FTP scan failed');
            }

            const deepResults = await response.json();
            console.log('📥 Deep FTP scan results:', deepResults);

            this.showDeepResults(deepResults, scanData);

        } catch (error) {
            console.error('❌ Deep FTP scan error:', error);
            window.ActiveScanUtils.showNotification(`Deep FTP scan failed: ${error.message}`, 'error');

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

    showDeepScanProgress(scanData) {
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

        // Simulate progress updates
        if (window.ActiveScanCoordinator && window.ActiveScanCoordinator.updateScanProgress) {
            window.ActiveScanCoordinator.updateScanProgress(25, 'Loading comprehensive NSE script suite...');
            setTimeout(() => window.ActiveScanCoordinator.updateScanProgress(50, 'Running ftp-* scripts...'), 1000);
            setTimeout(() => window.ActiveScanCoordinator.updateScanProgress(75, 'Analyzing deep findings...'), 2000);
            setTimeout(() => window.ActiveScanCoordinator.updateScanProgress(100, 'Deep FTP scan completed'), 3000);
        }
    }

    showDeepResults(deepResults, originalResults) {
        console.log('🔍 Showing deep FTP scan results');

        const progressSection = document.getElementById('scanProgressSection');
        if (progressSection) progressSection.classList.add('hidden');

        const resultsContent = document.getElementById('resultsContent');
        if (!resultsContent) return;

        // Add deep scan indicator
        const deepIndicator = document.createElement('div');
        deepIndicator.className = 'deep-scan-results-indicator';
        deepIndicator.innerHTML = `
            <div class="deep-scan-banner">
                ⚡ Deep FTP Scan Output
                <span class="deep-scan-badge">Raw Results</span>
            </div>
        `;

        resultsContent.insertBefore(deepIndicator, resultsContent.firstChild);

        // Show raw nmap output
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

        window.ActiveScanUtils.showNotification('Deep FTP scan completed', 'success');

        setTimeout(() => {
            resultsContent.scrollIntoView({ behavior: 'smooth' });
        }, 300);
    }

    renderServiceInfo(serviceInfo) {
        let html = super.renderServiceInfo(serviceInfo);

        // Add FTP-specific fields
        if (serviceInfo.server_type) {
            html += `
                <div class="service-detail-row">
                    <span class="service-label">FTP Server:</span>
                    <span class="service-value">${window.ActiveScanUtils.safeDisplayValue(serviceInfo.server_type)}</span>
                </div>
            `;
        }

        if (serviceInfo.anonymous_login !== undefined) {
            html += `
                <div class="service-detail-row">
                    <span class="service-label">Anonymous Login:</span>
                    <span class="service-value">${serviceInfo.anonymous_login ? '⚠️ Enabled' : '✅ Disabled'}</span>
                </div>
            `;
        }

        return html;
    }

    formatAdvancedFindings(findings) {
        let html = '<div class="ftp-advanced-findings-content">';

        // Anonymous access results
        if (findings.anonymous_access) {
            html += this.formatAnonymousAccess(findings.anonymous_access);
        }

        // File system information
        if (findings.file_system_info) {
            html += this.formatFileSystemInfo(findings.file_system_info);
        }

        // Security tests
        if (findings.security_tests) {
            html += this.formatSecurityTests(findings.security_tests);
        }

        html += '</div>';
        return html;
    }

    formatAnonymousAccess(anonAccess) {
        return `
            <div class="ftp-finding-card">
                <h5>📁 Anonymous Access Analysis</h5>
                <div class="access-method-${anonAccess.allowed ? 'success' : 'failed'}">
                    Status: ${anonAccess.allowed ? 'ALLOWED' : 'DENIED'}
                </div>
                ${anonAccess.allowed ? `
                    <div class="ftp-details">
                        <p><strong>Readable:</strong> ${window.ActiveScanUtils.safeDisplayValue(anonAccess.readable)}</p>
                        <p><strong>Writable:</strong> ${window.ActiveScanUtils.safeDisplayValue(anonAccess.writable)}</p>
                        ${anonAccess.login_used ? `<p><strong>Login Used:</strong> ${window.ActiveScanUtils.safeDisplayValue(anonAccess.login_used)}</p>` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    }

    formatFileSystemInfo(fileSystemInfo) {
        if (!fileSystemInfo.file_types_found) return '';

        const fileTypes = fileSystemInfo.file_types_found;
        if (typeof fileTypes === 'object' && Object.keys(fileTypes).length > 0) {
            return `
                <div class="ftp-finding-card">
                    <h5>📂 File System Analysis</h5>
                    <div class="ftp-file-types">
                        ${Object.entries(fileTypes)
                            .map(([ext, count]) => `<span class="file-type-badge">${ext}: ${window.ActiveScanUtils.safeDisplayValue(count)}</span>`)
                            .join('')}
                    </div>
                </div>
            `;
        }
        return '';
    }

    formatSecurityTests(secTests) {
        return `
            <div class="ftp-finding-card">
                <h5>🔒 Security Assessment</h5>
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

    injectCSS() {
        if (document.getElementById('ftp-scanner-css')) return;

        const style = document.createElement('style');
        style.id = 'ftp-scanner-css';
        style.textContent = `
            .deep-ftp-scan-btn {
                background: linear-gradient(135deg, #f59e0b, #d97706);
                border: none;
                color: white;
                font-weight: 600;
                transition: all 0.3s ease;
            }
            .deep-ftp-scan-btn:hover {
                background: linear-gradient(135deg, #d97706, #b45309);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
            }
            .deep-ftp-scan-btn:disabled {
                opacity: 0.6;
                transform: none;
                box-shadow: none;
            }
            .deep-ftp-scan-btn svg {
                width: 1rem;
                height: 1rem;
                margin-right: 0.5rem;
            }
            .ftp-finding-card {
                margin: 1rem 0;
                padding: 1rem;
                background: var(--bg-card);
                border-radius: 8px;
                border-left: 4px solid #059669;
            }
            .ftp-finding-card h5 {
                color: #059669;
                margin: 0 0 1rem 0;
            }
            .access-method-success {
                background: rgba(239, 68, 68, 0.1);
                color: #ef4444;
                padding: 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }
            .access-method-failed {
                background: rgba(16, 185, 129, 0.1);
                color: #10b981;
                padding: 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }
            .ftp-details {
                margin-top: 1rem;
                padding: 0.75rem;
                background: var(--bg-surface);
                border-radius: 4px;
            }
            .ftp-file-types {
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-top: 0.5rem;
            }
            .file-type-badge {
                background: rgba(59, 130, 246, 0.1);
                color: #3b82f6;
                padding: 0.25rem 0.75rem;
                border-radius: 12px;
                font-size: 0.8rem;
                font-weight: 600;
            }
            .security-tests {
                display: grid;
                gap: 0.5rem;
                margin-top: 0.5rem;
            }
            .security-critical {
                background: rgba(239, 68, 68, 0.1);
                color: #ef4444;
                padding: 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }
            .security-warning {
                background: rgba(245, 158, 11, 0.1);
                color: #f59e0b;
                padding: 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }
            .security-good {
                background: rgba(16, 185, 129, 0.1);
                color: #10b981;
                padding: 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }
        `;
        document.head.appendChild(style);
    }
}

// Register the FTP scanner
window.FTPScanner = FTPScanner;

console.log('✅ FTPScanner loaded');