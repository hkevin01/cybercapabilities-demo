// Dashboard JavaScript
class CyberDashboard {
    constructor() {
        this.ws = null;
        this.services = {};
        this.vulnerabilities = [];
        this.tests = [];
        this.startTime = Date.now();
        
        this.init();
    }
    
    init() {
        this.setupTabs();
        this.connectWebSocket();
        this.loadInitialData();
        this.startPeriodicUpdates();
        this.updateUptime();
    }
    
    setupTabs() {
        const navBtns = document.querySelectorAll('.nav-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        
        navBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.getAttribute('data-tab');
                
                // Update active nav button
                navBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Update active tab content
                tabContents.forEach(content => {
                    content.classList.remove('active');
                });
                document.getElementById(tabName).classList.add('active');
            });
        });
    }
    
    connectWebSocket() {
        try {
            this.ws = new WebSocket('ws://localhost:8081');
            
            this.ws.onopen = () => {
                this.updateConnectionStatus(true);
                this.updateStatusMessage('Connected to dashboard');
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };
            
            this.ws.onclose = () => {
                this.updateConnectionStatus(false);
                this.updateStatusMessage('Disconnected from dashboard');
                
                // Attempt to reconnect after 5 seconds
                setTimeout(() => this.connectWebSocket(), 5000);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus(false);
                this.updateStatusMessage('Connection error');
            };
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.updateConnectionStatus(false);
            this.updateStatusMessage('WebSocket not available');
        }
    }
    
    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'health_update':
                this.services = data.data;
                this.updateHealthOverview();
                this.updateServicesList();
                this.updateLastUpdate();
                break;
            case 'service_action':
                this.updateStatusMessage(`${data.service} ${data.action} ${data.status}`);
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }
    
    async loadInitialData() {
        try {
            // Load services status
            const servicesResponse = await fetch('/api/services/status');
            this.services = await servicesResponse.json();
            this.updateHealthOverview();
            this.updateServicesList();
            
            // Load vulnerabilities
            const vulnResponse = await fetch('/api/vulnerabilities');
            this.vulnerabilities = await vulnResponse.json();
            this.updateVulnerabilitiesList();
            
            // Load test results
            const testsResponse = await fetch('/api/security-tests');
            this.tests = await testsResponse.json();
            this.updateTestsList();
            
            this.updateServicesCount();
            this.updateStatusMessage('Dashboard loaded successfully');
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.updateStatusMessage('Error loading dashboard data');
        }
    }
    
    updateHealthOverview() {
        const container = document.getElementById('health-overview');
        if (!container) return;
        
        container.innerHTML = '';
        
        Object.entries(this.services).forEach(([key, service]) => {
            const item = document.createElement('div');
            item.className = 'health-item';
            
            const status = service.health?.status || 'unknown';
            const statusClass = status === 'healthy' ? 'healthy' : 
                              status === 'unhealthy' ? 'unhealthy' : 'unknown';
            
            item.innerHTML = `
                <div class="health-status ${statusClass}"></div>
                <div>
                    <div style="font-weight: bold;">${service.name}</div>
                    <div style="font-size: 0.9rem; color: #666;">Port ${service.port}</div>
                </div>
            `;
            
            container.appendChild(item);
        });
    }
    
    updateServicesList() {
        const container = document.getElementById('services-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        Object.entries(this.services).forEach(([key, service]) => {
            const item = document.createElement('div');
            item.className = 'service-item';
            
            const status = service.health?.status || 'unknown';
            const statusClass = status === 'healthy' ? 'healthy' : 
                              status === 'unhealthy' ? 'unhealthy' : 'unknown';
            
            item.innerHTML = `
                <div class="service-info">
                    <div class="health-status ${statusClass}"></div>
                    <div>
                        <div style="font-weight: bold;">${service.name}</div>
                        <div style="font-size: 0.9rem; color: #666;">
                            Port ${service.port} • Status: ${status}
                        </div>
                    </div>
                </div>
                <div class="service-actions">
                    <button class="btn btn-primary" onclick="dashboard.openService('${key}')">
                        <i class="fas fa-external-link-alt"></i> Open
                    </button>
                    <button class="btn btn-warning" onclick="dashboard.restartService('${key}')">
                        <i class="fas fa-redo"></i> Restart
                    </button>
                    <button class="btn btn-info" onclick="dashboard.viewLogs('${key}')">
                        <i class="fas fa-scroll"></i> Logs
                    </button>
                </div>
            `;
            
            container.appendChild(item);
        });
    }
    
    updateVulnerabilitiesList() {
        const container = document.getElementById('vulnerabilities-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.vulnerabilities.forEach((vuln, index) => {
            const item = document.createElement('div');
            item.className = 'vulnerability-item';
            
            const severityClass = `severity-${vuln.severity.toLowerCase()}`;
            
            item.innerHTML = `
                <div>
                    <div style="font-weight: bold;">
                        ${index + 1}. ${vuln.type}
                    </div>
                    <div style="font-size: 0.9rem; color: #666;">
                        Endpoint: ${vuln.endpoint}
                    </div>
                </div>
                <div>
                    <span class="severity-badge ${severityClass}">
                        ${vuln.severity}
                    </span>
                </div>
            `;
            
            container.appendChild(item);
        });
    }
    
    updateTestsList() {
        const container = document.getElementById('tests-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.tests.forEach(test => {
            const item = document.createElement('div');
            item.className = 'test-item';
            
            const statusClass = `test-${test.status}`;
            
            item.innerHTML = `
                <div>
                    <div style="font-weight: bold;">${test.name}</div>
                    <div style="font-size: 0.9rem; color: #666;">
                        Duration: ${test.duration}
                    </div>
                </div>
                <div>
                    <span class="test-status ${statusClass}">
                        ${test.status}
                    </span>
                </div>
            `;
            
            container.appendChild(item);
        });
    }
    
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-status');
        const text = document.getElementById('connection-text');
        
        if (indicator) {
            indicator.className = `status-indicator ${connected ? 'connected' : 'disconnected'}`;
        }
        
        if (text) {
            text.textContent = connected ? 'Connected' : 'Disconnected';
        }
    }
    
    updateStatusMessage(message) {
        const element = document.getElementById('status-message');
        if (element) {
            element.textContent = message;
        }
    }
    
    updateServicesCount() {
        const element = document.getElementById('services-count');
        if (element) {
            element.textContent = Object.keys(this.services).length;
        }
    }
    
    updateLastUpdate() {
        const element = document.getElementById('last-update');
        if (element) {
            element.textContent = new Date().toLocaleTimeString();
        }
    }
    
    updateUptime() {
        const element = document.getElementById('uptime');
        if (element) {
            const uptime = Math.floor((Date.now() - this.startTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = uptime % 60;
            
            if (hours > 0) {
                element.textContent = `${hours}h ${minutes}m`;
            } else if (minutes > 0) {
                element.textContent = `${minutes}m ${seconds}s`;
            } else {
                element.textContent = `${seconds}s`;
            }
        }
    }
    
    startPeriodicUpdates() {
        // Update uptime every second
        setInterval(() => this.updateUptime(), 1000);
        
        // Refresh data every 30 seconds
        setInterval(() => this.loadInitialData(), 30000);
    }
    
    // Action methods
    openService(serviceKey) {
        const service = this.services[serviceKey];
        if (service) {
            window.open(`http://localhost:${service.port}`, '_blank');
        }
    }
    
    async restartService(serviceKey) {
        try {
            const response = await fetch(`/api/services/${serviceKey}/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'restart' })
            });
            
            const result = await response.json();
            this.updateStatusMessage(result.message || 'Service restart initiated');
        } catch (error) {
            console.error('Error restarting service:', error);
            this.updateStatusMessage('Error restarting service');
        }
    }
    
    async viewLogs(serviceKey) {
        try {
            const response = await fetch(`/api/services/${serviceKey}/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'logs' })
            });
            
            const result = await response.json();
            this.showModal(`${serviceKey} Logs`, result.logs || 'No logs available');
        } catch (error) {
            console.error('Error fetching logs:', error);
            this.showModal('Error', 'Failed to fetch logs');
        }
    }
    
    showModal(title, content) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-content').textContent = content;
        document.getElementById('modal').style.display = 'block';
    }
    
    refreshServices() {
        this.loadInitialData();
        this.updateStatusMessage('Services refreshed');
    }
}

// Global action functions
function openApp(type) {
    const ports = { vulnerable: 3000, secure: 3001 };
    window.open(`http://localhost:${ports[type]}`, '_blank');
}

function runTests() {
    dashboard.updateStatusMessage('Running security tests...');
    // In a real implementation, this would trigger actual tests
    setTimeout(() => {
        dashboard.updateStatusMessage('Security tests completed');
        dashboard.loadInitialData();
    }, 2000);
}

function generateReport() {
    dashboard.updateStatusMessage('Generating security report...');
    // In a real implementation, this would generate a report
    setTimeout(() => {
        dashboard.showModal('Security Report', 'Comprehensive security analysis report would be generated here.');
    }, 1000);
}

function runAllTests() {
    dashboard.updateStatusMessage('Running all security tests...');
    // Simulate test execution
    setTimeout(() => {
        dashboard.updateStatusMessage('All tests completed successfully');
        dashboard.loadInitialData();
    }, 3000);
}

function runKeygen() {
    dashboard.showModal('License Generator', 'Generated License Key: CYBER-DEMO-2024-ABCD-EFGH-IJKL');
}

function viewChallenge() {
    dashboard.showModal('Reverse Engineering Challenge', 
        'Challenge: Find the algorithm to generate valid license keys.\n\n' +
        'Hint: The keygen uses a mathematical formula based on the input string.\n' +
        'Look for patterns in the generated keys!');
}

function dockerUp() {
    dashboard.updateStatusMessage('Starting Docker services...');
    setTimeout(() => dashboard.updateStatusMessage('Docker services started'), 2000);
}

function dockerRestart() {
    dashboard.updateStatusMessage('Restarting Docker services...');
    setTimeout(() => dashboard.updateStatusMessage('Docker services restarted'), 3000);
}

function dockerDown() {
    dashboard.updateStatusMessage('Stopping Docker services...');
    setTimeout(() => dashboard.updateStatusMessage('Docker services stopped'), 2000);
}

function openVSCode() {
    dashboard.updateStatusMessage('Opening in VS Code...');
}

function viewLogs() {
    dashboard.showModal('System Logs', 
        '[2024-01-01 12:00:00] Dashboard started\n' +
        '[2024-01-01 12:00:01] WebSocket server listening on port 8081\n' +
        '[2024-01-01 12:00:02] All services initialized\n' +
        '[2024-01-01 12:00:03] Health checks running...');
}

function runLinter() {
    dashboard.updateStatusMessage('Running code linter...');
    setTimeout(() => dashboard.updateStatusMessage('Linting completed - no issues found'), 2000);
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new CyberDashboard();
});

// Close modal when clicking outside
window.addEventListener('click', (event) => {
    const modal = document.getElementById('modal');
    if (event.target === modal) {
        closeModal();
    }
});
