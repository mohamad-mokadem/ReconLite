window.ActiveScanUtils = {
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

        const toast = document.createElement('div');
        toast.className = `notification ${type}`;

        let backgroundColor, icon = '';
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
        `;
        toast.textContent = icon + message;
        document.body.appendChild(toast);

        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, type === 'error' ? 6000 : 4000);
    },

    safeDisplayValue: function(value) {
        if (value === null || value === undefined || value === '') {
            return '';
        }
        if (typeof value === 'string') {
            return value.trim();
        }
        if (typeof value === 'number') {
            return value.toString();
        }
        if (typeof value === 'boolean') {
            return value ? 'Yes' : 'No';
        }
        if (Array.isArray(value)) {
            if (value.length === 0) return '';
            if (value.every(item => typeof item === 'string' || typeof item === 'number')) {
                return value.slice(0, 3).join(', ') + (value.length > 3 ? ` (+${value.length - 3} more)` : '');
            }
            return `${value.length} items`;
        }
        if (typeof value === 'object' && value !== null) {
            if (value.name) return this.safeDisplayValue(value.name);
            if (value.title) return this.safeDisplayValue(value.title);
            const entries = Object.entries(value);
            if (entries.length <= 3) {
                return entries.map(([k, v]) => `${k}: ${this.safeDisplayValue(v)}`).join(', ');
            }
            return `{${entries.length} properties}`;
        }
        return String(value);
    },

    getServiceType: function(port) {
        const serviceMap = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            80: 'HTTP',
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
    },

    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    downloadFile: function(content, filename) {
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
};

// Add CSS animations
if (!document.getElementById('slideInAnimation')) {
    const style = document.createElement('style');
    style.id = 'slideInAnimation';
    style.textContent = `
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(100%); }
            to { opacity: 1; transform: translateX(0); }
        }
        @keyframes slideOut {
            from { opacity: 1; transform: translateX(0); }
            to { opacity: 0; transform: translateX(100%); }
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .spinning {
            animation: spin 1s linear infinite;
        }
    `;
    document.head.appendChild(style);
}

console.log('✅ ActiveScanUtils loaded');