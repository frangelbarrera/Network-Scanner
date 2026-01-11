import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000, // 60 seconds for long-running scans
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for auth
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    return Promise.reject(error.response?.data || error.message);
  }
);

const apiService = {
  // Health check
  healthCheck: () => apiClient.get('/health'),

  // Reconnaissance endpoints
  scanSubdomains: (domain) => apiClient.post('/scan/subdomain', { domain }),
  
  scanPorts: (target, portRange = '1-1000') => 
    apiClient.post('/scan/ports', { target, port_range: portRange }),
  
  whoisLookup: (domain) => apiClient.post('/scan/whois', { domain }),
  
  dnsEnumeration: (domain) => apiClient.post('/scan/dns', { domain }),

  // Vulnerability scanning
  scanVulnerabilities: (target, scanType = 'basic') =>
    apiClient.post('/vulnerability/scan', { target, scan_type: scanType }),

  // AI Assistant
  chatWithAI: (message, context = {}) =>
    apiClient.post('/ai/chat', { message, context }),

  // Report generation
  generateReport: (scanData, format = 'html') =>
    apiClient.post('/report/generate', { scan_data: scanData, format }),

  // Mock endpoints for scan history (would be real database calls)
  getScanHistory: async () => {
    // This would be a real API call in production
    const stored = localStorage.getItem('scanHistory');
    return stored ? JSON.parse(stored) : [];
  },

  saveScanResult: async (scanResult) => {
    // This would be a real API call in production
    const history = await apiService.getScanHistory();
    const updated = [scanResult, ...history.slice(0, 49)]; // Keep last 50
    localStorage.setItem('scanHistory', JSON.stringify(updated));
    return scanResult;
  },

  // User management (placeholder)
  getCurrentUser: () => {
    return {
      id: 1,
      username: 'demo_user',
      email: 'demo@secscanx.com',
      role: 'user',
      learning_mode: true
    };
  },

  updateUserSettings: (settings) => {
    // Mock implementation
    return Promise.resolve(settings);
  },

  // Project management (placeholder)
  getProjects: () => {
    const stored = localStorage.getItem('projects');
    return Promise.resolve(stored ? JSON.parse(stored) : []);
  },

  createProject: (project) => {
    const projects = JSON.parse(localStorage.getItem('projects') || '[]');
    const newProject = {
      ...project,
      id: Date.now(),
      created_at: new Date().toISOString(),
      scan_count: 0
    };
    projects.push(newProject);
    localStorage.setItem('projects', JSON.stringify(projects));
    return Promise.resolve(newProject);
  },

  // Statistics (mock)
  getStatistics: () => {
    return Promise.resolve({
      total_scans: 42,
      vulnerabilities_found: 156,
      critical_vulnerabilities: 8,
      targets_scanned: 15,
      success_rate: 94.2
    });
  }
};

export default apiService;
