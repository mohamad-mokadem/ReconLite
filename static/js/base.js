// Base JavaScript - Shared functionality across all pages

// Global state
let globalState = {
    currentUser: null,
    systemStatus: 'ready',
    notifications: [],
    theme: 'dark'
};

// Initialize base functionality
document.addEventListener('DOMContentLoaded', function() {
    initializeBase();
    updateSystemStatus();
    loadUserPreferences();
});

function initializeBase() {
    // Initialize notification system
    setupNotificationSystem();

    // Initialize global event listeners
    setupGlobalEventListeners();

    // Initialize tooltips and interactive elements
    setupInteractiveElements();

    // Check for saved sessions
    updateSessionCounts();
}

// Notification System
function setupNotificationSystem() {
    const container = document.getElementById('notifications');
    if (!container) return;

    // Create notification container if it doesn't exist
    container.className = 'notifications-container';
}

function showNotification(message, type = 'info', duration = 5000) {
    const container = document.getElementById('notifications');
    if (!container) return;

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    notification.innerHTML = `
        <div class="notification-icon">${icons[type] || icons.info}</div>
        <div class="notification-content">
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close" onclick="removeNotification(this.parentNode)">×</button>
    `;

    container.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('notification-show'), 100);

    // Auto remove
    if (duration > 0) {
        setTimeout(() => removeNotification(notification), duration);
    }

    return notification;
}

function removeNotification(notification) {
    if (!notification) return;

    notification.classList.add('notification-hide');
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 300);
}

// System Status Management
function updateSystemStatus(status = 'ready', message = null) {
    globalState.systemStatus = status;

    const statusDot = document.getElementById('systemStatusDot');
    const statusText = document.getElementById('systemStatusText');

    if (statusDot) {
        statusDot.className = 'status-dot';
        statusDot.classList.add(`status-${status}`);
    }

    if (statusText) {
        const statusMessages = {
            ready: 'Ready',
            scanning: 'Scanning...',
            processing: 'Processing...',
            error: 'Error',
            offline: 'Offline'
        };

        statusText.textContent = message || statusMessages[status] || 'Unknown';
    }
}

// Global Event Listeners
function setupGlobalEventListeners() {
    // Escape key to close modals
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });

    // Click outside modal to close
    document.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal-overlay')) {
            closeAllModals();
        }
    });

    // Handle navigation active states
    updateNavigationActiveStates();
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal-overlay');
    modals.forEach(modal => {
        modal.classList.remove('active');
    });
    document.body.style.overflow = '';
}

function updateNavigationActiveStates() {
    const navItems = document.querySelectorAll('.nav-item');
    const currentPath = window.location.pathname;

    navItems.forEach(item => {
        const href = item.getAttribute('href');
        if (href && currentPath.includes(href) && href !== '/') {
            item.classList.add('active');
        } else if (href === '/' && currentPath === '/') {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

// Interactive Elements
function setupInteractiveElements() {
    // Add loading states to buttons
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function(event) {
            if (!this.disabled && !this.classList.contains('btn-loading')) {
                this.classList.add('btn-pulse');
                setTimeout(() => this.classList.remove('btn-pulse'), 600);
            }
        });
    });

    // Add hover effects to cards
    const cards = document.querySelectorAll('.action-card, .session-card, .template-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-4px)';
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
}

// Utility Functions
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 1) {
        return 'Yesterday';
    } else if (diffDays < 7) {
        return `${diffDays} days ago`;
    } else {
        return date.toLocaleDateString();
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
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

// Session Management Utilities
function updateSessionCounts() {
    try {
        const sessions = getSavedSessions();
        const totalSessions = sessions.length;
        const passiveSessions = sessions.filter(s => s.type === 'passive').length;
        const activeSessions = sessions.filter(s => s.type === 'active').length;

        // Update counts in various elements
        updateElementText('totalSessionsCount', totalSessions);
        updateElementText('passiveSessionsCount', passiveSessions);
        updateElementText('activeSessionsCount', activeSessions);
        updateElementText('savedSessionsCount', totalSessions);

        // Calculate total size
        const totalSize = sessions.reduce((acc, session) => {
            return acc + (session.size || 0);
        }, 0);
        updateElementText('totalSizeCount', formatFileSize(totalSize));

    } catch (error) {
        console.error('Error updating session counts:', error);
    }
}

function updateElementText(id, text) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = text;
    }
}

function getSavedSessions() {
    try {
        const sessions = localStorage.getItem('reconlite_sessions');
        return sessions ? JSON.parse(sessions) : [];
    } catch (error) {
        console.error('Error loading sessions:', error);
        return [];
    }
}

function saveSession(sessionData) {
    try {
        const sessions = getSavedSessions();
        sessionData.id = sessionData.id || generateSessionId();
        sessionData.created_at = sessionData.created_at || new Date().toISOString();
        sessionData.size = JSON.stringify(sessionData).length;

        // Remove existing session with same ID
        const filteredSessions = sessions.filter(s => s.id !== sessionData.id);
        filteredSessions.push(sessionData);

        localStorage.setItem('reconlite_sessions', JSON.stringify(filteredSessions));
        updateSessionCounts();

        showNotification('Session saved successfully', 'success');
        return sessionData.id;
    } catch (error) {
        console.error('Error saving session:', error);
        showNotification('Failed to save session', 'error');
        return null;
    }
}

function loadSession(sessionId) {
    try {
        const sessions = getSavedSessions();
        const session = sessions.find(s => s.id === sessionId);

        if (session) {
            showNotification('Session loaded successfully', 'success');
            return session;
        } else {
            showNotification('Session not found', 'error');
            return null;
        }
    } catch (error) {
        console.error('Error loading session:', error);
        showNotification('Failed to load session', 'error');
        return null;
    }
}

function deleteSession(sessionId) {
    try {
        const sessions = getSavedSessions();
        const filteredSessions = sessions.filter(s => s.id !== sessionId);

        localStorage.setItem('reconlite_sessions', JSON.stringify(filteredSessions));
        updateSessionCounts();

        showNotification('Session deleted successfully', 'success');
        return true;
    } catch (error) {
        console.error('Error deleting session:', error);
        showNotification('Failed to delete session', 'error');
        return false;
    }
}

// User Preferences
function loadUserPreferences() {
   try {
       const preferences = localStorage.getItem('reconlite_preferences');
       if (preferences) {
           const prefs = JSON.parse(preferences);
           globalState.theme = prefs.theme || 'dark';
           applyTheme(globalState.theme);
       }
   } catch (error) {
       console.error('Error loading preferences:', error);
   }
}

function saveUserPreferences() {
   try {
       const preferences = {
           theme: globalState.theme,
           lastVisited: new Date().toISOString()
       };
       localStorage.setItem('reconlite_preferences', JSON.stringify(preferences));
   } catch (error) {
       console.error('Error saving preferences:', error);
   }
}

function applyTheme(theme) {
   document.documentElement.setAttribute('data-theme', theme);
   globalState.theme = theme;
   saveUserPreferences();
}

// API Utilities
async function makeRequest(url, options = {}) {
   try {
       updateSystemStatus('processing');

       const defaultOptions = {
           headers: {
               'Content-Type': 'application/json',
           },
       };

       const response = await fetch(url, { ...defaultOptions, ...options });

       if (!response.ok) {
           const errorData = await response.json().catch(() => ({}));
           throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
       }

       updateSystemStatus('ready');
       return await response.json();
   } catch (error) {
       updateSystemStatus('error', error.message);
       console.error('API Request failed:', error);
       throw error;
   }
}

// Export/Import Utilities
function downloadFile(content, filename, mimeType = 'application/json') {
   const blob = new Blob([content], { type: mimeType });
   const url = URL.createObjectURL(blob);
   const a = document.createElement('a');
   a.href = url;
   a.download = filename;
   document.body.appendChild(a);
   a.click();
   document.body.removeChild(a);
   URL.revokeObjectURL(url);
}

function readFileAsText(file) {
   return new Promise((resolve, reject) => {
       const reader = new FileReader();
       reader.onload = (e) => resolve(e.target.result);
       reader.onerror = (e) => reject(e);
       reader.readAsText(file);
   });
}

// Animation Utilities
function animateCounter(elementId, target, duration = 1000) {
   const element = document.getElementById(elementId);
   if (!element) return;

   const start = parseInt(element.textContent) || 0;
   const startTime = performance.now();

   function updateCounter(currentTime) {
       const elapsed = currentTime - startTime;
       const progress = Math.min(elapsed / duration, 1);

       const current = Math.floor(start + (target - start) * progress);
       element.textContent = current;

       if (progress < 1) {
           requestAnimationFrame(updateCounter);
       }
   }

   requestAnimationFrame(updateCounter);
}

// Form Validation Utilities
function validateIP(ip) {
   const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
   return ipRegex.test(ip);
}

function validateDomain(domain) {
   const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
   return domainRegex.test(domain);
}

function validatePort(port) {
   const portNum = parseInt(port);
   return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
}



// Error Handling
function handleError(error, context = '') {
   console.error(`Error in ${context}:`, error);

   let message = 'An unexpected error occurred';
   if (typeof error === 'string') {
       message = error;
   } else if (error.message) {
       message = error.message;
   }

   showNotification(message, 'error');
   updateSystemStatus('error', message);
}

// Data Storage Utilities
function saveToLocalStorage(key, data) {
   try {
       localStorage.setItem(key, JSON.stringify(data));
       return true;
   } catch (error) {
       console.error('Error saving to localStorage:', error);
       return false;
   }
}

function loadFromLocalStorage(key, defaultValue = null) {
   try {
       const data = localStorage.getItem(key);
       return data ? JSON.parse(data) : defaultValue;
   } catch (error) {
       console.error('Error loading from localStorage:', error);
       return defaultValue;
   }
}

// Network Status Detection
function checkNetworkStatus() {
   return new Promise((resolve) => {
       const timeout = setTimeout(() => resolve(false), 5000);

       fetch('/api/health', { method: 'HEAD' })
           .then(() => {
               clearTimeout(timeout);
               resolve(true);
           })
           .catch(() => {
               clearTimeout(timeout);
               resolve(false);
           });
   });
}

// Initialize network status monitoring
let networkStatusInterval;
function startNetworkMonitoring() {
   networkStatusInterval = setInterval(async () => {
       const isOnline = await checkNetworkStatus();
       updateSystemStatus(isOnline ? 'ready' : 'offline');
   }, 30000); // Check every 30 seconds
}

function stopNetworkMonitoring() {
   if (networkStatusInterval) {
       clearInterval(networkStatusInterval);
       networkStatusInterval = null;
   }
}

// Initialize network monitoring when page loads
document.addEventListener('DOMContentLoaded', () => {
   startNetworkMonitoring();
});

// Clean up when page unloads
window.addEventListener('beforeunload', () => {
   stopNetworkMonitoring();
});

// Global keyboard shortcuts
document.addEventListener('keydown', function(event) {
   // Ctrl/Cmd + K for quick search (if search exists)
   if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
       event.preventDefault();
       const searchInput = document.querySelector('#searchSessions, .search-input');
       if (searchInput) {
           searchInput.focus();
       }
   }

   // Ctrl/Cmd + N for new scan
   if ((event.ctrlKey || event.metaKey) && event.key === 'n') {
       event.preventDefault();
       window.location.href = '/active-scan';
   }

   // Ctrl/Cmd + S for save (if applicable)
   if ((event.ctrlKey || event.metaKey) && event.key === 's') {
       event.preventDefault();
       const saveButton = document.querySelector('[onclick*="save"], .save-btn');
       if (saveButton) {
           saveButton.click();
       }
   }
});

// Performance monitoring
function measurePerformance(name, fn) {
   const start = performance.now();
   const result = fn();
   const end = performance.now();
   console.log(`${name} took ${end - start} milliseconds`);
   return result;
}

// Async performance monitoring
async function measureAsyncPerformance(name, fn) {
   const start = performance.now();
   const result = await fn();
   const end = performance.now();
   console.log(`${name} took ${end - start} milliseconds`);
   return result;
}

// Add CSS for notification system
const notificationStyles = `
.notifications-container {
   position: fixed;
   top: 2rem;
   right: 2rem;
   z-index: 1000;
   display: flex;
   flex-direction: column;
   gap: 0.5rem;
   max-width: 400px;
}

.notification {
   background: var(--bg-surface);
   border: 1px solid var(--border-default);
   border-radius: 12px;
   padding: 1rem;
   box-shadow: var(--shadow-lg);
   display: flex;
   align-items: flex-start;
   gap: 0.75rem;
   transform: translateX(100%);
   opacity: 0;
   transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
   backdrop-filter: blur(16px);
}

.notification-show {
   transform: translateX(0);
   opacity: 1;
}

.notification-hide {
   transform: translateX(100%);
   opacity: 0;
}

.notification-success {
   border-left: 4px solid var(--success);
}

.notification-error {
   border-left: 4px solid var(--danger);
}

.notification-warning {
   border-left: 4px solid var(--warning);
}

.notification-info {
   border-left: 4px solid var(--primary);
}

.notification-icon {
   width: 20px;
   height: 20px;
   border-radius: 50%;
   display: flex;
   align-items: center;
   justify-content: center;
   font-size: 0.875rem;
   font-weight: bold;
   flex-shrink: 0;
}

.notification-success .notification-icon {
   background: var(--success);
   color: white;
}

.notification-error .notification-icon {
   background: var(--danger);
   color: white;
}

.notification-warning .notification-icon {
   background: var(--warning);
   color: white;
}

.notification-info .notification-icon {
   background: var(--primary);
   color: white;
}

.notification-content {
   flex: 1;
}

.notification-message {
   color: var(--text-primary);
   font-size: 0.875rem;
   font-weight: 500;
   line-height: 1.4;
}

.notification-close {
   background: none;
   border: none;
   color: var(--text-muted);
   cursor: pointer;
   font-size: 1.25rem;
   padding: 0;
   width: 20px;
   height: 20px;
   display: flex;
   align-items: center;
   justify-content: center;
   border-radius: 4px;
   transition: var(--transition);
}

.notification-close:hover {
   color: var(--text-primary);
   background: var(--bg-elevated);
}

.btn-pulse {
   animation: btnPulse 0.6s ease-out;
}

@keyframes btnPulse {
   0% { transform: scale(1); }
   50% { transform: scale(0.95); }
   100% { transform: scale(1); }
}

.status-ready { background: var(--success); }
.status-scanning, .status-processing { background: var(--warning); }
.status-error { background: var(--danger); }
.status-offline { background: var(--text-muted); }

@media (max-width: 768px) {
   .notifications-container {
       top: 1rem;
       right: 1rem;
       left: 1rem;
       max-width: none;
   }
   
   .notification {
       padding: 0.875rem;
   }
}
`;

// Inject notification styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// Export utilities for other modules
window.ReconLiteUtils = {
   showNotification,
   updateSystemStatus,
   formatDate,
   formatFileSize,
   validateIP,
   validateDomain,
   validatePort,
   makeRequest,
   downloadFile,
   readFileAsText,
   animateCounter,
   handleError,
   saveToLocalStorage,
   loadFromLocalStorage,
   getSavedSessions,
   saveSession,
   loadSession,
   deleteSession,
   generateSessionId,
   debounce,
   measurePerformance,
   measureAsyncPerformance
};