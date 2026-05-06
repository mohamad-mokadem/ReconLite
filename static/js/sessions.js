
console.log('📋 Loading Simplified Sessions Manager');


window.ReconLiteSessions = window.ReconLiteSessions || {
    initialized: false,
    currentView: 'grid',
    allSessions: [],
    filteredSessions: [],
    loading: false
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeSessions);
} else {
    initializeSessions();
}

function initializeSessions() {
    if (window.ReconLiteSessions.initialized) {
        console.log('⚠️ Sessions already initialized');
        return;
    }

    console.log('📋 Initializing Sessions Manager...');

    try {
        setupEventListeners();
        loadSessionsOnce();

        // Check for URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        const viewSessionId = urlParams.get('view');
        if (viewSessionId) {
            setTimeout(() => viewSessionDetails(viewSessionId), 1000);
        }

        // Set default view to list
        window.ReconLiteSessions.currentView = 'table';

        window.ReconLiteSessions.initialized = true;
        console.log('✅ Sessions Manager initialized with list view');

    } catch (error) {
        console.error('❌ Sessions initialization failed:', error);
    }
}

function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('searchSessions');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(filterSessions, 300));
    }

    // Filter dropdowns
    const typeFilter = document.getElementById('typeFilter');
    const dateFilter = document.getElementById('dateFilter');

    if (typeFilter) typeFilter.addEventListener('change', filterSessions);
    if (dateFilter) dateFilter.addEventListener('change', filterSessions);

    // View toggle buttons
    const viewButtons = document.querySelectorAll('.view-btn');
    viewButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            if (view) switchView(view);
        });
    });

    console.log('✅ Sessions event listeners setup');
}

async function loadSessionsOnce() {
    if (window.ReconLiteSessions.loading) {
        console.log('⚠️ Already loading sessions');
        return;
    }

    console.log('📊 Loading sessions (one-time load)...');
    window.ReconLiteSessions.loading = true;

    try {
        const response = await fetch('/api/sessions');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const rawSessions = await response.json();
        console.log('📊 Raw sessions received:', rawSessions);

        // Process sessions
        let sessions = [];
        if (Array.isArray(rawSessions)) {
            sessions = rawSessions;
        } else if (rawSessions && Array.isArray(rawSessions.data)) {
            sessions = rawSessions.data;
        } else if (rawSessions) {
            sessions = [rawSessions];
        }

        // Clean and validate sessions
        const validSessions = sessions
            .filter(session => session && session.id)
            .map(session => ({
                id: session.id,
                name: session.name || 'Unnamed Session',
                type: session.type || 'unknown',
                target: session.target || 'Unknown Target',
                created_at: session.created_at,
                completed_at: session.completed_at,
                status: session.status || 'unknown',
                service_count: parseInt(session.service_count) || 0,
                vulnerability_count: parseInt(session.vulnerability_count) || 0,
                size: calculateSessionSize(session)
            }));

        window.ReconLiteSessions.allSessions = validSessions;
        window.ReconLiteSessions.filteredSessions = [...validSessions];

        console.log('📊 Processed', validSessions.length, 'valid sessions');

        // Update display
        displaySessions();
        updateSessionStats();

        console.log('✅ Sessions loaded successfully');

    } catch (error) {
        console.error('❌ Error loading sessions:', error);
        showNotification('Error loading sessions: ' + error.message, 'error');

        // Show empty state
        window.ReconLiteSessions.allSessions = [];
        window.ReconLiteSessions.filteredSessions = [];
        displaySessions();

    } finally {
        window.ReconLiteSessions.loading = false;
    }
}

function displaySessions() {
    const sessions = window.ReconLiteSessions.filteredSessions;
    console.log('🎨 Displaying', sessions.length, 'sessions in', window.ReconLiteSessions.currentView, 'view');

    if (window.ReconLiteSessions.currentView === 'grid') {
        displaySessionsGrid(sessions);
    } else {
        displaySessionsTable(sessions);
    }

    // Handle empty state
    const isEmpty = sessions.length === 0;
    const emptyState = document.getElementById('emptyState');
    const gridContainer = document.getElementById('sessionsGrid');
    const tableContainer = document.getElementById('sessionsList');

    if (emptyState) emptyState.style.display = isEmpty ? 'block' : 'none';
    if (gridContainer) gridContainer.style.display = (isEmpty || window.ReconLiteSessions.currentView !== 'grid') ? 'none' : 'grid';
    if (tableContainer) tableContainer.style.display = (isEmpty || window.ReconLiteSessions.currentView !== 'table') ? 'none' : 'block';
}












function switchView(view) {
    console.log('👁️ Switching to', view, 'view');

    // Map the view names correctly
    if (view === 'list') {
        window.ReconLiteSessions.currentView = 'table';
    } else {
        window.ReconLiteSessions.currentView = view;
    }

    // Update button states
    document.querySelectorAll('.view-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });

    displaySessions();
}

function filterSessions() {
    const searchTerm = document.getElementById('searchSessions')?.value.toLowerCase() || '';
    const typeFilter = document.getElementById('typeFilter')?.value || 'all';
    const dateFilter = document.getElementById('dateFilter')?.value || 'all';

    console.log('🔍 Filtering:', { searchTerm, typeFilter, dateFilter });

    window.ReconLiteSessions.filteredSessions = window.ReconLiteSessions.allSessions.filter(session => {
        const matchesSearch = !searchTerm ||
            session.name.toLowerCase().includes(searchTerm) ||
            session.target.toLowerCase().includes(searchTerm) ||
            session.type.toLowerCase().includes(searchTerm);

        const matchesType = typeFilter === 'all' || session.type === typeFilter;

        let matchesDate = true;
        if (dateFilter !== 'all') {
            const sessionDate = new Date(session.created_at);
            const now = new Date();

            switch (dateFilter) {
                case 'today':
                    matchesDate = sessionDate.toDateString() === now.toDateString();
                    break;
                case 'week':
                    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    matchesDate = sessionDate >= weekAgo;
                    break;
                case 'month':
                    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    matchesDate = sessionDate >= monthAgo;
                    break;
            }
        }

        return matchesSearch && matchesType && matchesDate;
    });

    console.log('🔍 Filtered to', window.ReconLiteSessions.filteredSessions.length, 'sessions');
    displaySessions();
}

async function viewSessionDetails(sessionId) {
    console.log('👁️ Loading session details for:', sessionId);

    try {
        const response = await fetch(`/api/sessions/${sessionId}`);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }

        const session = await response.json();
        console.log('📊 Session details received:', session);

        // Show modal
        const modal = document.getElementById('sessionModal');
        const modalTitle = document.getElementById('sessionModalTitle');
        const sessionDetails = document.getElementById('sessionDetails');

        if (modal && modalTitle && sessionDetails) {
            modalTitle.textContent = session.name || 'Session Details';

            sessionDetails.innerHTML = `
                <div class="detail-section">
                    <h4>Basic Information</h4>
                    <p><strong>Name:</strong> ${session.name || 'Unnamed Session'}</p>
                    <p><strong>Type:</strong> ${session.type}</p>
                    <p><strong>Target:</strong> ${session.target}</p>
                    <p><strong>Status:</strong> ${session.status}</p>
                    <p><strong>Created:</strong> ${new Date(session.created_at).toLocaleString()}</p>
                </div>
                <div class="detail-section">
                    <h4>Results</h4>
                    <p><strong>Services:</strong> ${session.services ? session.services.length : 0}</p>
                    ${session.type === 'passive' ? 
                        `<p><strong>Subdomains:</strong> ${session.subdomains ? session.subdomains.length : 0}</p>
                         <p><strong>DNS Records:</strong> ${session.dns_records ? session.dns_records.length : 0}</p>` :
                        `<p><strong>Vulnerabilities:</strong> ${session.vulnerabilities ? session.vulnerabilities.length : 0}</p>`
                    }
                </div>
            `;

            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }

    } catch (error) {
        console.error('❌ Error loading session details:', error);
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function deleteSessionConfirm(sessionId) {
    const session = window.ReconLiteSessions.allSessions.find(s => s.id === sessionId);
    if (!session) return;

    if (confirm(`Delete session "${session.name}"?`)) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}`, { method: 'DELETE' });

            if (response.ok) {
                // Remove from local data
                window.ReconLiteSessions.allSessions = window.ReconLiteSessions.allSessions.filter(s => s.id !== sessionId);
                window.ReconLiteSessions.filteredSessions = window.ReconLiteSessions.filteredSessions.filter(s => s.id !== sessionId);

                // Update display
                displaySessions();
                updateSessionStats();

                showNotification('Session deleted successfully', 'success');
                console.log('✅ Session deleted:', sessionId);
            } else {
                throw new Error('Delete failed');
            }
        } catch (error) {
            console.error('❌ Delete error:', error);
            showNotification('Error deleting session', 'error');
        }
    }
}

async function loadSessionData(sessionId) {
    console.log('📂 Loading COMPLETE session data:', sessionId);

    const session = window.ReconLiteSessions.allSessions.find(s => s.id === sessionId);
    if (!session) {
        showNotification('Session not found', 'error');
        return;
    }

    try {
        showNotification('Loading complete session data...', 'info');

        // Use the enhanced complete endpoint
        const response = await fetch(`/api/sessions/${sessionId}/complete`);

        if (!response.ok) {
            throw new Error(`Failed to load session: ${response.status} ${response.statusText}`);
        }

        const completeSessionData = await response.json();
        console.log('📊 COMPLETE session data received:', completeSessionData);

        if (session.type === 'passive') {
            console.log('🔍 Loading COMPLETE PASSIVE scan session');

            // Store enhanced session data
            sessionStorage.setItem('loadedPassiveScan', JSON.stringify(completeSessionData));
            console.log('💾 Stored COMPLETE passive scan data in sessionStorage');

            showNotification(`Loading "${session.name}" - All data included`, 'success');

            setTimeout(() => {
                window.location.href = '/passive-scan?loaded=true';
            }, 1000);

        } else if (session.type === 'active') {
            console.log('🔍 Loading COMPLETE ACTIVE scan session');

            // Store enhanced session data
            sessionStorage.setItem('loadedActiveScan', JSON.stringify(completeSessionData));
            console.log('💾 Stored COMPLETE active scan data in sessionStorage');

            const vulnCount = completeSessionData.scan_results?.scan_summary?.total_vulnerabilities || 0;
            showNotification(`Loading "${session.name}" - ${vulnCount} vulnerabilities included`, 'success');

            setTimeout(() => {
                window.location.href = '/active-scan?loaded=true';
            }, 1000);
        }

    } catch (error) {
        console.error('❌ Error loading COMPLETE session:', error);
        showNotification('Failed to load complete session: ' + error.message, 'error');
    }
}



function formatCleanShodanIntelligence(completeSession) {
    // Check if Shodan data exists but clean it properly
    const shodanData = completeSession.shodan_intelligence ||
                       completeSession.shodan_data ||
                       completeSession.shodan_host_intelligence;

    if (!shodanData) {
        return {
            available: false,
            message: 'No Shodan intelligence available for this session'
        };
    }

    // Clean Shodan data to prevent [object Object] display
    const cleanShodan = {
        available: true,
        host_found: true,
        scan_time: completeSession.created_at
    };

    // Only add string/number values, avoid objects
    if (shodanData.ip_str) cleanShodan.ip = shodanData.ip_str;
    if (shodanData.country_name) cleanShodan.country = shodanData.country_name;
    if (shodanData.city) cleanShodan.city = shodanData.city;
    if (shodanData.org) cleanShodan.organization = shodanData.org;
    if (shodanData.isp) cleanShodan.isp = shodanData.isp;

    // Format host summary with safe values only
    cleanShodan.host_summary = {
        ip: shodanData.ip_str || '',
        country: shodanData.country_name || '',
        city: shodanData.city || '',
        org: shodanData.org || '',
        isp: shodanData.isp || '',
        total_ports: Array.isArray(shodanData.data) ? shodanData.data.length : 0
    };

    return cleanShodan;
}

function formatCleanAdvancedFindings(completeSession) {
    const findings = completeSession.advanced_findings || {};
    const cleanFindings = {};

    // Only include simple key-value pairs, avoid nested objects
    for (const [key, value] of Object.entries(findings)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            cleanFindings[key] = value;
        } else if (Array.isArray(value)) {
            // For arrays, only include if they contain simple values
            if (value.length > 0 && typeof value[0] === 'string') {
                cleanFindings[key] = value.slice(0, 5); // Limit array size
            }
        }
    }

    return cleanFindings;
}



function formatSecurityTrailsRecords(dnsRecords) {
    console.log('🔍 SESSIONS: formatSecurityTrailsRecords input:', dnsRecords);

    if (!Array.isArray(dnsRecords)) {
        console.warn('⚠️ SESSIONS: DNS records is not an array for SecurityTrails:', dnsRecords);
        return [];
    }

    const formatted = dnsRecords
        .filter(record => record && (record.source === 'SecurityTrails' || !record.source))
        .map(record => ({
            type: record.record_type || record.type || 'Unknown',
            name: record.domain || record.name || '',
            value: record.record_value || record.value || ''
        }));

    console.log('✅ SESSIONS: Formatted SecurityTrails records:', formatted);
    return formatted;
}

function formatServicesForUI(services) {
    console.log('🔍 SESSIONS: formatServicesForUI input:', services);

    if (!Array.isArray(services)) {
        console.warn('⚠️ SESSIONS: Services is not an array:', services);
        return [];
    }

    const formatted = services.map(service => {
        console.log('🔍 SESSIONS: Processing service:', service);

        return {
            // Core service information
            ip: service.ip_address || service.ip || 'Unknown',
            port: service.port || 0,
            protocol: service.protocol || 'tcp',
            service: service.service_name || service.service || 'unknown',
            version: service.service_version || service.version || '',
            banner: service.banner || '',
            state: service.state || 'open',

            // Enhanced display properties
            display_name: `${service.service_name || service.service || 'Unknown Service'} (${service.port || 'N/A'})`,
            service_description: generateServiceDescription(service),
            risk_level: assessServiceRisk(service),

            // Additional properties that might be present in database
            country: service.country || '',
            organization: service.organization || service.org || '',
            source: service.source || '',
            asn: service.asn || '',
            http_title: service.http_title || '',
            http_server: service.http_server || ''
        };
    });

    console.log('✅ SESSIONS: Formatted services:', formatted);
    return formatted;
}



function formatDNSRecords(dnsRecords) {
    console.log('🔍 SESSIONS: formatDNSRecords input:', dnsRecords);

    if (!Array.isArray(dnsRecords)) {
        console.warn('⚠️ SESSIONS: DNS records is not an array:', dnsRecords);
        return {};
    }

    const formatted = {};
    dnsRecords.forEach(record => {
        if (record && record.record_type && record.record_value) {
            const type = record.record_type;
            if (!formatted[type]) {
                formatted[type] = [];
            }
            formatted[type].push(record.record_value);
        }
    });

    console.log('✅ SESSIONS: Formatted DNS records:', formatted);
    return formatted;
}

function parseWhoisData(whoisData) {
    console.log('🔍 WHOIS: Raw whois data from database:', whoisData);

    if (!whoisData || whoisData.length === 0) {
        console.log('⚠️ WHOIS: No whois data available');
        return {};
    }

    const firstRecord = whoisData[0];
    console.log('🔍 WHOIS: First record:', firstRecord);

    let parsedWhois = {};


    if (firstRecord.raw_data) {
        try {
            console.log('🔍 WHOIS: Raw data found, converting Python dict to JSON...');

            // Convert Python dictionary string to valid JSON
            let jsonStr = firstRecord.raw_data
                .replace(/'/g, '"')           // Replace single quotes with double quotes
                .replace(/None/g, 'null')     // Replace Python None with null
                .replace(/True/g, 'true')     // Replace Python True with true
                .replace(/False/g, 'false')   // Replace Python False with false
                .replace(/\n/g, ' ')          // Remove newlines
                .replace(/\s+/g, ' ')         // Normalize whitespace
                .trim();

            console.log('🔍 WHOIS: Converted JSON string:', jsonStr);

            parsedWhois = JSON.parse(jsonStr);
            console.log('✅ WHOIS: Successfully parsed Python dict as JSON');

        } catch (jsonError) {
            console.log('⚠️ WHOIS: JSON conversion failed, trying manual extraction');
            console.log('⚠️ WHOIS: Error:', jsonError.message);

            // Manual extraction as fallback
            parsedWhois = extractWhoisManually(firstRecord.raw_data);
        }
    }

    // Fallback to database column values if parsing failed
    if (Object.keys(parsedWhois).length === 0) {
        console.log('🔍 WHOIS: Using database columns as fallback');
        parsedWhois = {
            domain_name: firstRecord.domain || '',
            registrar: firstRecord.registrar || '',
            creation_date: firstRecord.creation_date || '',
            expiration_date: firstRecord.expiration_date || ''
        };
    }


    parsedWhois = cleanWhoisData(parsedWhois);

    console.log('✅ WHOIS: Final parsed data:', parsedWhois);
    return parsedWhois;
}


function extractWhoisManually(rawDataStr) {
    console.log('🔧 WHOIS: Manual extraction from:', rawDataStr);

    const extracted = {};

    // Patterns to match Python dict values
    const patterns = {
        domain_name: /'domain_name':\s*'([^']+)'/i,
        registrar: /'registrar':\s*'([^']+)'/i,
        creation_date: /'creation_date':\s*'([^']+)'/i,
        expiration_date: /'expiration_date':\s*'([^']+)'/i,
        updated_date: /'updated_date':\s*'([^']+)'/i,
        registrant_org: /'registrant_org':\s*'([^']+)'/i,
        admin_email: /'admin_email':\s*'([^']+)'/i,
        country: /'country':\s*'([^']+)'/i,
        domain_age_years: /'domain_age_years':\s*(\d+)/i,
        whois_server: /'whois_server':\s*'([^']+)'/i
    };

    // Extract other fields
    for (const [key, pattern] of Object.entries(patterns)) {
        const match = rawDataStr.match(pattern);
        if (match && match[1]) {
            if (key === 'domain_age_years') {
                extracted[key] = parseInt(match[1]);
            } else {
                extracted[key] = match[1].trim();
            }
            console.log(`✅ WHOIS: Extracted ${key}:`, extracted[key]);
        }
    }

    console.log('🔧 WHOIS: Manual extraction result:', extracted);
    return extracted;
}

function cleanWhoisData(whoisData) {
    const cleaned = {};

    // Clean and validate each field
    for (const [key, value] of Object.entries(whoisData)) {
        if (value !== null && value !== undefined && value !== '') {
            if (typeof value === 'string') {
                // Clean string values
                cleaned[key] = value.trim();
            } else if (Array.isArray(value)) {
                // Clean array values
                cleaned[key] = value.filter(item => item && item.trim() !== '');
            } else {
                // Keep other types as-is
                cleaned[key] = value;
            }
        }
    }

    console.log('🧹 WHOIS: Cleaned data:', cleaned);
    return cleaned;
}



function updateSessionStats() {
    const sessions = window.ReconLiteSessions.allSessions;
    const totalSessions = sessions.length;
    const passiveSessions = sessions.filter(s => s.type === 'passive').length;
    const activeSessions = sessions.filter(s => s.type === 'active').length;
    const totalSize = sessions.reduce((acc, session) => acc + session.size, 0);

    // Update stat elements if they exist
    const updates = [
        { id: 'totalSessionsCount', value: totalSessions },
        { id: 'passiveSessionsCount', value: passiveSessions },
        { id: 'activeSessionsCount', value: activeSessions },
        { id: 'totalSizeCount', value: formatFileSize(totalSize), isText: true }
    ];

    updates.forEach(({ id, value, isText }) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = isText ? value : value;
        }
    });
}

function clearFilters() {
    const searchInput = document.getElementById('searchSessions');
    const typeFilter = document.getElementById('typeFilter');
    const dateFilter = document.getElementById('dateFilter');

    if (searchInput) searchInput.value = '';
    if (typeFilter) typeFilter.value = 'all';
    if (dateFilter) dateFilter.value = 'all';

    filterSessions();
    showNotification('Filters cleared', 'success');
}

// Modal functions
function closeSessionModal() {
    const modal = document.getElementById('sessionModal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// Utility functions
function calculateSessionSize(session) {
    let size = 1024; // Base size
    if (session.service_count) size += session.service_count * 512;
    if (session.vulnerability_count) size += session.vulnerability_count * 256;
    return size;
}

function formatDate(dateString) {
    try {
        if (!dateString) return 'Unknown';
        return new Date(dateString).toLocaleDateString();
    } catch {
        return 'Unknown';
    }
}

function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function showNotification(message, type = 'info') {
    // Remove existing notifications
    document.querySelectorAll('.notification').forEach(n => n.remove());

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    // Enhanced styling based on type
    const typeStyles = {
        info: 'background: linear-gradient(135deg, #3b82f6, #2563eb); border-left: 4px solid #1e40af;',
        success: 'background: linear-gradient(135deg, #10b981, #059669); border-left: 4px solid #047857;',
        error: 'background: linear-gradient(135deg, #ef4444, #dc2626); border-left: 4px solid #b91c1c;',
        warning: 'background: linear-gradient(135deg, #f59e0b, #d97706); border-left: 4px solid #b45309;'
    };

    notification.style.cssText = `
        position: fixed; top: 2rem; right: 2rem; z-index: 1001;
        padding: 1rem 1.5rem; border-radius: 12px; color: white; font-weight: 600;
        ${typeStyles[type]}
        animation: slideIn 0.4s ease; cursor: pointer; max-width: 400px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        backdrop-filter: blur(10px);
        font-family: 'Inter', sans-serif;
    `;

    // Add icon based on type
    const icons = {
        info: '📘',
        success: '✅',
        error: '❌',
        warning: '⚠️'
    };

    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.2em;">${icons[type] || '📋'}</span>
            <span>${message}</span>
        </div>
    `;

    notification.onclick = () => notification.remove();
    document.body.appendChild(notification);

    // Auto-remove with different timings based on type
    const autoRemoveTime = type === 'error' ? 8000 : type === 'success' ? 3000 : 5000;
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, autoRemoveTime);
}

// Manual refresh function (no auto-refresh)
function refreshSessions() {
    console.log('🔄 Manual refresh sessions');
    loadSessionsOnce();
}

// Global functions for manual control
window.refreshSessions = refreshSessions;
window.debugSessions = function() {
    console.log('🔍 Sessions Debug:');
    console.log('State:', window.ReconLiteSessions);
    console.log('All sessions:', window.ReconLiteSessions.allSessions.length);
    console.log('Filtered sessions:', window.ReconLiteSessions.filteredSessions.length);
    console.log('Current view:', window.ReconLiteSessions.currentView);
};

// Add required CSS animations
if (!document.getElementById('sessionsCSS')) {
    const style = document.createElement('style');
    style.id = 'sessionsCSS';
    style.textContent = `
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(100%); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .session-status.completed { color: #10b981; }
        .session-status.in_progress { color: #f59e0b; }
        .session-status.failed { color: #ef4444; }
        
        .notification {
            pointer-events: auto;
            transition: all 0.3s ease;
        }
    `;
    document.head.appendChild(style);
}

// Add these functions at the end of your sessions.js
function importSession() {
    const modal = document.getElementById('importSessionModal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function createNewSession() {
    const choice = confirm('Create a new session:\n\nOK = Passive Scan\nCancel = Active Scan');
    if (choice) {
        window.location.href = '/passive-scan';
    } else {
        window.location.href = '/active-scan';
    }
}

function closeImportSessionModal() {
    const modal = document.getElementById('importSessionModal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function generateServiceDescription(service) {
    const serviceName = service.service_name || service.service || 'Unknown';
    const version = service.service_version || service.version;

    if (version) {
        return `${serviceName} ${version}`;
    }

    const serviceDescriptions = {
        'ssh': 'Secure Shell - Remote access protocol',
        'http': 'Web server - HTTP protocol',
        'https': 'Secure web server - HTTPS protocol',
        'ftp': 'File Transfer Protocol',
        'smtp': 'Simple Mail Transfer Protocol',
        'dns': 'Domain Name System',
        'mysql': 'MySQL Database Server',
        'postgresql': 'PostgreSQL Database Server'
    };

    return serviceDescriptions[serviceName.toLowerCase()] || serviceName;
}


function assessServiceRisk(service) {
    const highRiskPorts = [21, 23, 135, 139, 445, 1433, 3389];
    const mediumRiskPorts = [22, 25, 53, 110, 143, 993, 995];

    const port = parseInt(service.port);

    if (highRiskPorts.includes(port)) return 'high';
    if (mediumRiskPorts.includes(port)) return 'medium';
    return 'low';
}

function formatSubdomainsForUI(subdomains) {
    console.log('🔍 SESSIONS: formatSubdomainsForUI input:', subdomains);
    console.log('🔍 SESSIONS: Subdomains type:', typeof subdomains, 'isArray:', Array.isArray(subdomains));

    if (!subdomains) {
        console.log('⚠️ SESSIONS: No subdomains provided');
        return [];
    }

    if (!Array.isArray(subdomains)) {
        console.warn('⚠️ SESSIONS: Subdomains is not an array:', subdomains);
        return [];
    }

    const formatted = subdomains
        .map((sub, index) => {
            console.log(`🔍 SESSIONS: Processing subdomain ${index}:`, sub, typeof sub);

            // Handle different database formats
            if (typeof sub === 'string') {
                return {
                    subdomain: sub,
                    display_name: sub,
                    category: categorizeSubdomain(sub)
                };
            } else if (sub && typeof sub === 'object') {
                // Handle database object format
                const subdomain = sub.subdomain || sub.name || sub.domain || sub.hostname || String(sub);
                return {
                    subdomain: subdomain,
                    display_name: subdomain,
                    category: categorizeSubdomain(subdomain),
                    discovered_method: sub.discovered_method || 'Certificate Transparency'
                };
            } else {
                console.warn('⚠️ SESSIONS: Unknown subdomain format:', sub);
                return {
                    subdomain: String(sub),
                    display_name: String(sub),
                    category: 'General'
                };
            }
        })
        .filter(sub => sub.subdomain && sub.subdomain.trim() !== '')
        .filter(sub => sub.subdomain !== 'undefined' && sub.subdomain !== 'null');

    console.log('✅ SESSIONS: Final formatted subdomains:', formatted);
    return formatted;
}



function categorizeSubdomain(subdomain){
    const categories = {
        'www': 'Web',
        'mail': 'Email',
        'ftp': 'File Transfer',
        'admin': 'Administrative',
        'api': 'API',
        'dev': 'Development',
        'test': 'Testing',
        'staging': 'Staging',
        'blog': 'Content',
        'shop': 'E-commerce'
    };

    const prefix = subdomain.split('.')[0].toLowerCase();
    return categories[prefix] || 'General';
}


function getBestBanner(services) {
    if (!Array.isArray(services) || services.length === 0) {
        return 'Service detected but no banner available';
    }

    const service = services[0];
    return service.banner ||
           `${service.service_name || 'Unknown'} service on port ${service.port || 'N/A'}`;
}



function generateEnhancedRecommendations(vulnerabilities, scanType) {
    const recommendations = ['Keep service updated to latest version'];

    if (vulnerabilities.length > 0) {
        recommendations.push('Address identified vulnerabilities immediately');

        const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
        if (criticalCount > 0) {
            recommendations.unshift(`🚨 URGENT: ${criticalCount} critical vulnerabilities require immediate attention`);
        }

        const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
        if (highCount > 0) {
            recommendations.push(`⚠️ HIGH PRIORITY: ${highCount} high severity vulnerabilities found`);
        }
    }

    // Service-specific recommendations
    const serviceRecs = {
        ssh: 'Disable password authentication and use key-based authentication',
        ftp: 'Consider using SFTP instead of FTP for secure file transfer',
        smtp: 'Enable STARTTLS and implement proper email security',
        http: 'Migrate to HTTPS and implement security headers',
        https: 'Ensure SSL/TLS configuration follows best practices',
        smb: 'Disable SMB v1 and enable SMB signing',
        snmp: 'Change default community strings and restrict access',
        dns: 'Disable recursive queries for external clients'
    };

    if (serviceRecs[scanType]) {
        recommendations.push(serviceRecs[scanType]);
    }

    recommendations.push('Monitor service logs for suspicious activity');
    recommendations.push('Implement network segmentation and access controls');

    return recommendations;
}






function formatActiveScanResults(completeSession, targetIP, targetPort, scanType, sessionId) {
    console.log('🔍 SESSIONS: formatActiveScanResults called with:', {
        targetIP, targetPort, scanType, sessionId
    });
    console.log('🔍 SESSIONS: Complete session data:', completeSession);

    // Combine ALL vulnerability types
    const regularVulnerabilities = completeSession.vulnerabilities || [];
    const cveVulnerabilities = completeSession.cve_vulnerabilities || [];
    const allVulnerabilities = [...regularVulnerabilities, ...cveVulnerabilities];

    // Enhanced service information extraction
    const services = completeSession.services || [];
    const primaryService = services.length > 0 ? services[0] : {};

    // Create comprehensive scan results
    const results = {
        // Basic target information
        target: completeSession.target || `${targetIP}:${targetPort}`,
        ip: targetIP,
        port: parseInt(targetPort),
        service_type: scanType,
        service_name: primaryService.service_name || primaryService.service || scanType,
        status: 'completed',
        scan_time: completeSession.created_at,

        // Enhanced banner information
        banner: getBestBanner(services) || primaryService.banner ||
                `${scanType.toUpperCase()} service detected on port ${targetPort}`,

        // Comprehensive service information
        service_info: formatEnhancedServiceInfo(primaryService, services, scanType),

        // All vulnerabilities (regular + CVE)
        vulnerabilities: allVulnerabilities,
        cve_vulnerabilities: cveVulnerabilities,

        // Enhanced recommendations
        recommendations: generateEnhancedRecommendations(allVulnerabilities, scanType),

        // CVE Analysis (if available)
        cve_enabled: cveVulnerabilities.length > 0,
        cve_analysis: formatCVEAnalysis(completeSession),

        // Advanced findings (if available)
        advanced_findings: formatCleanAdvancedFindings(completeSession),

        // Shodan intelligence (if available)
        shodan_intelligence: formatCleanShodanIntelligence(completeSession),

        // Session metadata
        session_id: sessionId,
        enhanced_mode: true,

        // UI-friendly summary
        scan_summary: {
            total_vulnerabilities: allVulnerabilities.length,
            critical_count: allVulnerabilities.filter(v => v.severity === 'Critical').length,
            high_count: allVulnerabilities.filter(v => v.severity === 'High').length,
            medium_count: allVulnerabilities.filter(v => v.severity === 'Medium').length,
            low_count: allVulnerabilities.filter(v => v.severity === 'Low').length,
            service_name: scanType.toUpperCase(),
            scan_duration: completeSession.scan_duration || 'Unknown',
            cve_count: cveVulnerabilities.length,
            regular_vuln_count: regularVulnerabilities.length
        }
    };

    console.log('✅ SESSIONS: Enhanced formatActiveScanResults result:', results);
    return results;
}

function formatEnhancedServiceInfo(primaryService, allServices, scanType) {
    console.log('🔍 SESSIONS: formatEnhancedServiceInfo input:', {
        primaryService, allServices, scanType
    });

    if (!primaryService || Object.keys(primaryService).length === 0) {
        // Create basic service info if none exists
        return {
            service_name: scanType.toUpperCase(),
            accessible: true,
            port_status: 'open',
            scan_completed: true
        };
    }

    const serviceInfo = {
        // Basic service information
        service_name: primaryService.service_name || primaryService.service || scanType,
        service_version: primaryService.service_version || primaryService.version || '',
        banner: primaryService.banner || '',
        port_status: primaryService.state || 'open',
        accessible: true,
        protocol: primaryService.protocol || 'tcp',

        // Additional metadata
        ip_address: primaryService.ip_address || primaryService.ip || '',
        port: primaryService.port || '',

        // Enhanced fields that might be missing
        scan_completed: true,
        response_time_ms: primaryService.response_time_ms || primaryService.connection_time || null
    };

    // Add any additional service-specific fields (preserve original data)
    Object.keys(primaryService).forEach(key => {
        if (!serviceInfo.hasOwnProperty(key) &&
            primaryService[key] !== null &&
            primaryService[key] !== undefined &&
            primaryService[key] !== '') {

            // Only add simple values to avoid [object Object] display
            if (typeof primaryService[key] === 'string' ||
                typeof primaryService[key] === 'number' ||
                typeof primaryService[key] === 'boolean') {
                serviceInfo[key] = primaryService[key];
            }
        }
    });

    console.log('✅ SESSIONS: Enhanced service info result:', serviceInfo);
    return serviceInfo;
}

function formatCVEAnalysis(completeSession) {
    const detectedSoftware = completeSession.detected_software || [];
    const cveVulnerabilities = completeSession.cve_vulnerabilities || [];

    if (detectedSoftware.length === 0 && cveVulnerabilities.length === 0) {
        return null;
    }

    return {
        detected_software: detectedSoftware.map(software => ({
            name: software.software_name || software.name || 'Unknown',
            version: software.version || 'Unknown',
            cpe: software.cpe || '',
            confidence: software.confidence || 'medium',
            detection_method: software.detection_method || 'banner_analysis'
        })),
        total_cve_vulnerabilities: cveVulnerabilities.length,
        cve_sources: ['NVD', 'CVE Database'],
        software_analysis_completed: true
    };
}

function displaySessionsGrid(sessions) {
    const container = document.getElementById('sessionsGrid');
    if (!container) return;

    if (sessions.length === 0) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = sessions.map(session => `
        <div class="session-card" onclick="viewSessionDetails('${session.id}')">
            <div class="session-card-header">
                <span class="session-type-badge ${session.type}">${session.type}</span>
                <span class="session-status ${session.status}">${session.status}</span>
            </div>
            
            <div class="session-card-content">
                <div class="session-name">${session.name}</div>
                <div class="session-target">${session.target}</div>
                
                <div class="session-stats">
                    <div class="session-stat">
                        <span class="stat-value">${session.service_count}</span>
                        <span class="stat-label">Services</span>
                    </div>
                    ${session.type === 'active' ? `
                        <div class="session-stat">
                            <span class="stat-value">${session.vulnerability_count}</span>
                            <span class="stat-label">Vulns</span>
                        </div>
                    ` : ''}
                </div>
                
                <div class="session-meta">
                    <span class="session-date">${formatDate(session.created_at)}</span>
                    <span class="session-size">${formatFileSize(session.size)}</span>
                </div>
            </div>
            
            <div class="session-actions" onclick="event.stopPropagation()">
                <button class="session-action-btn" onclick="loadSessionData('${session.id}')">Load</button>
                <button class="session-action-btn" onclick="exportSessionPDF('${session.id}')">Export</button>
                <button class="session-action-btn" onclick="deleteSessionConfirm('${session.id}')">Delete</button>
            </div>
        </div>
    `).join('');
}

function displaySessionsTable(sessions) {
    const tableBody = document.getElementById('sessionsTableBody');
    if (!tableBody) return;

    if (sessions.length === 0) {
        tableBody.innerHTML = '';
        return;
    }

    tableBody.innerHTML = sessions.map(session => `
        <tr onclick="viewSessionDetails('${session.id}')">
            <td class="table-session-name">${session.name}</td>
            <td><span class="session-type-badge ${session.type}">${session.type}</span></td>
            <td class="table-session-target">${session.target}</td>
            <td>${formatDate(session.created_at)}</td>
            <td>
                <div class="results-summary">
                    <span class="result-count">${session.service_count} services</span>
                    ${session.type === 'active' ? `<span class="vuln-count">${session.vulnerability_count} vulns</span>` : ''}
                </div>
            </td>
            <td>${formatFileSize(session.size)}</td>
            <td onclick="event.stopPropagation()">
                <div class="table-actions">
                    <button class="table-action-btn" onclick="loadSessionData('${session.id}')">Load</button>
                    <button class="table-action-btn" onclick="exportSessionPDF('${session.id}')">Export</button>
                    <button class="table-action-btn" onclick="deleteSessionConfirm('${session.id}')">Delete</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function exportSessionPDF(sessionId) {
    console.log('📄 Exporting session as PDF:', sessionId);

    try {
        showNotification('Generating PDF report...', 'info');

        const response = await fetch(`/api/sessions/${sessionId}/export`);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'PDF export failed' }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }

        const blob = await response.blob();
        const contentDisposition = response.headers.get('content-disposition');
        let filename = `session_${sessionId}_report.pdf`;

        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (filenameMatch && filenameMatch[1]) {
                filename = filenameMatch[1].replace(/['"]/g, '');
            }
        }

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();

        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showNotification(`PDF exported: ${filename}`, 'success');
        console.log('✅ PDF export completed:', filename);

    } catch (error) {
        console.error('❌ PDF export error:', error);
        showNotification(`PDF export failed: ${error.message}`, 'error');
    }
}

function determineTargetType(target) {
    if (!target) return 'unknown';

    // Check if it's an IP address
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(target)) {
        return 'ip';
    }

    // Check if it's a domain
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (domainPattern.test(target)) {
        return 'domain';
    }

    return 'unknown';
}