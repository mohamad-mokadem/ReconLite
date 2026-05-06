
console.log('📊 Loading Dashboard v1.0');

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('📋 Dashboard DOM loaded');
    initializeDashboard();
});

function initializeDashboard() {
    console.log('🚀 Initializing dashboard...');

    // Load stats
    loadDashboardStats();

    // Setup action cards
    setupActionCards();

    // Auto-refresh stats every 60 seconds
    setInterval(() => {
        console.log('⏰ Auto-refreshing stats');
        loadDashboardStats();
    }, 60000);

    console.log('✅ Dashboard initialized');
}

// Load dashboard statistics
async function loadDashboardStats() {
    console.log('📊 Loading dashboard stats...');

    try {
        const response = await fetch('/api/dashboard/stats');

        if (response.ok) {
            const stats = await response.json();
            console.log('📊 Stats received:', stats);

            // Update counters
            animateCounter('totalScansCount', stats.total_sessions || 0);
            animateCounter('savedSessionsCount', stats.total_sessions || 0);
            animateCounter('servicesFoundCount', stats.total_services || 0);

            console.log('✅ Stats updated');
        } else {
            console.warn('⚠️ Stats API returned:', response.status);
            // Fallback values
            updateElement('totalScansCount', 0);
            updateElement('savedSessionsCount', 0);
            updateElement('servicesFoundCount', 0);
        }

    } catch (error) {
        console.error('❌ Error loading stats:', error);
        // Fallback values
        updateElement('totalScansCount', 0);
        updateElement('savedSessionsCount', 0);
        updateElement('servicesFoundCount', 0);
    }
}

// Setup action cards
function setupActionCards() {
    const actionCards = document.querySelectorAll('.action-card');

    actionCards.forEach(card => {
        card.addEventListener('click', function(event) {
            // Don't trigger if clicking on a button inside the card
            if (event.target.closest('.btn')) return;

            const link = this.querySelector('a');
            if (link) {
                console.log('🎯 Navigating to:', link.href);
                window.location.href = link.href;
            }
        });
    });
}

// Animate counter with smooth transition
function animateCounter(elementId, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.warn(`⚠️ Element not found: ${elementId}`);
        return;
    }

    const currentValue = parseInt(element.textContent) || 0;
    const difference = targetValue - currentValue;

    if (difference === 0) return;

    const duration = 1000;
    const steps = 30;
    const stepValue = difference / steps;
    const stepDuration = duration / steps;

    let currentStep = 0;

    const timer = setInterval(() => {
        currentStep++;
        const newValue = Math.round(currentValue + (stepValue * currentStep));

        if (currentStep >= steps) {
            element.textContent = targetValue;
            clearInterval(timer);
        } else {
            element.textContent = newValue;
        }
    }, stepDuration);
}

// Update element directly
function updateElement(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

// Global functions for manual control
window.refreshStats = loadDashboardStats;
window.testDashboard = function() {
    console.log('🧪 Testing dashboard elements...');
    console.log('Elements:', {
        totalScansCount: !!document.getElementById('totalScansCount'),
        savedSessionsCount: !!document.getElementById('savedSessionsCount'),
        servicesFoundCount: !!document.getElementById('servicesFoundCount'),
        actionCards: document.querySelectorAll('.action-card').length
    });
};

console.log('✅ Dashboard JavaScript loaded');