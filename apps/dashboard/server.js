const express = require('express');
const cors = require('cors');
const WebSocket = require('ws');
const axios = require('axios');
const path = require('path');
const { spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// WebSocket server for real-time updates
const wss = new WebSocket.Server({ port: 8081 });

// Broadcast to all connected clients
function broadcast(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// Service health check endpoints
const services = {
  vulnerable: { name: 'Vulnerable App', port: 3000, url: 'http://localhost:3000/health' },
  secure: { name: 'Secure App', port: 3001, url: 'http://localhost:3001/health' },
  dashboard: { name: 'Dashboard', port: 8080, url: 'http://localhost:8080/health' }
};

// Health check function
async function checkServiceHealth(service) {
  try {
    const response = await axios.get(service.url, { timeout: 5000 });
    return { status: 'healthy', response: response.status };
  } catch (error) {
    return { status: 'unhealthy', error: error.message };
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/services/status', async (req, res) => {
  const statuses = {};
  
  for (const [key, service] of Object.entries(services)) {
    statuses[key] = {
      ...service,
      health: await checkServiceHealth(service)
    };
  }
  
  res.json(statuses);
});

app.post('/api/services/:service/action', async (req, res) => {
  const { service } = req.params;
  const { action } = req.body;
  
  try {
    switch (action) {
      case 'restart':
        // In a real implementation, this would restart the service
        broadcast({ type: 'service_action', service, action, status: 'success' });
        res.json({ success: true, message: `${service} restart initiated` });
        break;
      case 'logs':
        // In a real implementation, this would return service logs
        res.json({ logs: `Mock logs for ${service}` });
        break;
      default:
        res.status(400).json({ error: 'Unknown action' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/vulnerabilities', (req, res) => {
  const vulnerabilities = [
    { id: 1, type: 'SQL Injection', severity: 'Critical', endpoint: '/search' },
    { id: 2, type: 'XSS', severity: 'High', endpoint: '/comment' },
    { id: 3, type: 'Command Injection', severity: 'Critical', endpoint: '/ping' },
    { id: 4, type: 'SSRF', severity: 'Medium', endpoint: '/fetch' },
    { id: 5, type: 'File Upload', severity: 'High', endpoint: '/upload' },
    { id: 6, type: 'Broken Access Control', severity: 'High', endpoint: '/admin' },
    { id: 7, type: 'Security Misconfiguration', severity: 'Medium', endpoint: '/config' },
    { id: 8, type: 'XXE', severity: 'High', endpoint: '/xml' },
    { id: 9, type: 'Insecure Deserialization', severity: 'Critical', endpoint: '/deserialize' },
    { id: 10, type: 'Known Vulnerable Components', severity: 'Medium', endpoint: 'N/A' }
  ];
  
  res.json(vulnerabilities);
});

app.get('/api/security-tests', (req, res) => {
  const tests = [
    { name: 'OWASP ZAP Scan', status: 'passed', duration: '45s' },
    { name: 'SQL Injection Tests', status: 'passed', duration: '12s' },
    { name: 'XSS Tests', status: 'passed', duration: '8s' },
    { name: 'Authentication Tests', status: 'passed', duration: '15s' },
    { name: 'Authorization Tests', status: 'passed', duration: '10s' }
  ];
  
  res.json(tests);
});

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received:', data);
    } catch (error) {
      console.error('Invalid JSON:', error);
    }
  });
  
  ws.on('close', () => {
    console.log('Client disconnected from WebSocket');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Cybersecurity Dashboard running on http://localhost:${PORT}`);
  console.log(`📡 WebSocket server running on ws://localhost:8081`);
});

// Periodic health checks and updates
setInterval(async () => {
  const statuses = {};
  for (const [key, service] of Object.entries(services)) {
    statuses[key] = {
      ...service,
      health: await checkServiceHealth(service)
    };
  }
  
  broadcast({
    type: 'health_update',
    data: statuses,
    timestamp: new Date().toISOString()
  });
}, 30000); // Check every 30 seconds
