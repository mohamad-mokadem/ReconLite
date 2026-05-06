class BaseScanner {
    constructor(serviceType) {
        this.serviceType = serviceType;
        this.deepScanWarnings = {};
    }

    // Base method to render service information
    renderServiceInfo(serviceInfo) {
        let html = '';

        if (serviceInfo.service_name || this.serviceType) {
            html += `
                <div class="service-detail-row">
                    <span class="service-label">Service Type:</span>
                    <span class="service-value">${serviceInfo.service_name || this.serviceType.toUpperCase()}</span>
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
                    <span class="service-label">Service Banner:</span>
                    <span class="service-value banner-text">${window.ActiveScanUtils.safeDisplayValue(serviceInfo.banner)}</span>
                </div>
            `;
        }

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

        return html || this.getDefaultServiceInfo();
    }

    getDefaultServiceInfo() {
        return `
            <div class="service-detail-row">
                <span class="service-label">Service Detected:</span>
                <span class="service-value">${this.serviceType.toUpperCase()} service is running</span>
            </div>
            <div class="service-detail-row">
                <span class="service-label">Port Status:</span>
                <span class="service-value">✅ Open and Accessible</span>
            </div>
        `;
    }

    // Base method to render vulnerability items
    renderVulnerabilityItem(vuln) {
        const severityClass = (vuln.severity || 'info').toLowerCase();
        const source = vuln.source || `${this.serviceType}_scanner`;

        return `
            <div class="vulnerability-item ${severityClass}" data-source="${source}">
                <div class="vuln-header">
                    <div class="vuln-id-section">
                        <span class="vuln-id">${window.ActiveScanUtils.safeDisplayValue(vuln.id || 'FINDING')}</span>
                        <span class="scanner-badge">SCANNER</span>
                    </div>
                    <div class="vuln-severity-section">
                        <span class="vuln-severity ${severityClass}">${window.ActiveScanUtils.safeDisplayValue(vuln.severity || 'Info')}</span>
                    </div>
                </div>
                
                <div class="vuln-content">
                    <div class="vuln-title">${window.ActiveScanUtils.safeDisplayValue(vuln.title || 'Security Finding')}</div>
                    <div class="vuln-description">${window.ActiveScanUtils.safeDisplayValue(vuln.description || 'No description available')}</div>
                    
                    ${vuln.detection_method ? `
                        <div class="vuln-metadata">
                            <span class="metadata-item">
                                <strong>Detection Method:</strong> ${window.ActiveScanUtils.safeDisplayValue(vuln.detection_method)}
                            </span>
                        </div>
                    ` : ''}
                    
                    ${vuln.recommendation ? `
                        <div class="vuln-recommendation">
                            <strong>💡 Recommendation:</strong> ${window.ActiveScanUtils.safeDisplayValue(vuln.recommendation)}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    // Base method to render complete scan results
    renderScanResults(scanData) {
        let html = '';

        // Service information card
        html += `
            <div class="result-card">
                <h4>🎯 ${this.serviceType.toUpperCase()} Service Information</h4>
                <div class="result-details">
                    <div class="detail-row">
                        <span class="detail-label">Target:</span>
                        <span class="detail-value">${window.ActiveScanUtils.safeDisplayValue(scanData.target || `${scanData.ip}:${scanData.port}`)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Service Type:</span>
                        <span class="detail-value">${this.serviceType.toUpperCase()}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Scan Status:</span>
                        <span class="detail-value status-${scanData.status || 'unknown'}">
                            ${window.ActiveScanUtils.safeDisplayValue(scanData.status || 'Unknown').toUpperCase()}
                        </span>
                    </div>
                </div>
            </div>
        `;

        // Technical analysis card
        html += `
            <div class="result-card">
                <h4>🔍 Technical Analysis</h4>
                <div class="service-details">
                    ${this.renderServiceInfo(scanData.service_info || {})}
                </div>
            </div>
        `;

        // Nmap results if available
        if (scanData.nmap_data) {
            html += this.renderNmapResults(scanData.nmap_data);
        }

        // Advanced findings
        if (scanData.advanced_findings) {
            html += `
                <div class="result-card">
                    <h4>🚀 Advanced Findings</h4>
                    <div class="advanced-findings">
                        ${this.formatAdvancedFindings(scanData.advanced_findings)}
                    </div>
                </div>
            `;
        }

        // Vulnerabilities
        const vulnerabilities = scanData.vulnerabilities || [];
        if (vulnerabilities.length > 0) {
            html += this.renderVulnerabilitiesCard(vulnerabilities);
        } else {
            html += `
                <div class="result-card">
                    <h4>🛡️ Security Assessment</h4>
                    <div class="no-vulnerabilities">
                        <div class="success-icon">✅</div>
                        <p>No immediate security issues detected</p>
                        <small>This assessment covers ${this.serviceType.toUpperCase()} security configuration</small>
                    </div>
                </div>
            `;
        }

        return html;
    }

    renderNmapResults(nmapData) {
        if (nmapData.error) {
            return `
                <div class="result-card">
                    <h4>🔍 ${this.serviceType.toUpperCase()} Scan Status</h4>
                    <div class="nmap-error">
                        <p>Enhanced scan failed: ${window.ActiveScanUtils.safeDisplayValue(nmapData.error)}</p>
                        <small>Scanner used fallback analysis methods</small>
                    </div>
                </div>
            `;
        }

        return `
            <div class="result-card">
                <h4>🔍 ${this.serviceType.toUpperCase()} Security Scan Results</h4>
                <div class="nmap-display">
                    <div class="nmap-command">
                        <strong>Command:</strong> ${nmapData.command_used || `nmap scan for ${this.serviceType}`}
                    </div>
                    <div class="nmap-output">
                        <h6>📋 Key Security Results:</h6>
                        <pre class="nmap-formatted">${nmapData.formatted_for_display || 'No formatted output available'}</pre>
                        
                        <details class="nmap-full-output">
                            <summary>🔍 View Full Scan Output</summary>
                            <pre class="nmap-raw">${nmapData.raw_output || 'No raw output available'}</pre>
                        </details>
                    </div>
                </div>
            </div>
        `;
    }

    renderVulnerabilitiesCard(vulnerabilities) {
        const severityCounts = {
            'Critical': vulnerabilities.filter(v => v.severity === 'Critical').length,
            'High': vulnerabilities.filter(v => v.severity === 'High').length,
            'Medium': vulnerabilities.filter(v => v.severity === 'Medium').length,
            'Low': vulnerabilities.filter(v => v.severity === 'Low').length,
            'Info': vulnerabilities.filter(v => v.severity === 'Info' || v.severity === 'Informational').length
        };

        return `
            <div class="result-card">
                <h4>🛡️ Security Assessment</h4>
                <div class="vulnerabilities-section">
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
                    <div class="vulnerabilities-list">
                        ${vulnerabilities.map(vuln => this.renderVulnerabilityItem(vuln)).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    // Methods that subclasses should override
    showDeepScanButton(scanData) {
        console.log(`No deep scan implemented for ${this.serviceType}`);
    }

    formatAdvancedFindings(findings) {
        return `<p>No advanced findings formatter for ${this.serviceType}</p>`;
    }

    async startDeepScan(scanData) {
        throw new Error(`Deep scan not implemented for ${this.serviceType}`);
    }

    // Utility method to check if nmap data is available for deep scanning
    hasValidNmapData(scanData) {
        return scanData.nmap_data && !scanData.nmap_data.error;
    }
}

// Make BaseScanner available globally
window.BaseScanner = BaseScanner;

console.log('✅ BaseScanner loaded');