import React, { createContext, useContext, useState, useEffect } from 'react';
import io from 'socket.io-client';
import apiService, { getApiAccessToken } from '../services/apiService';

const ScanContext = createContext();
const REPORTS_STORAGE_KEY = 'network-scanner-reports';
const API_SETTINGS_STORAGE_KEY = 'network-scanner-api-settings';
const VULNERABILITY_SCAN_TYPES = new Set(['basic', 'web', 'network', 'comprehensive', 'vulnerability']);

const getSocketUrl = () => {
  if (process.env.REACT_APP_SOCKET_URL) {
    return process.env.REACT_APP_SOCKET_URL;
  }
  const configuredApiUrl = process.env.REACT_APP_API_URL;
  return configuredApiUrl ? configuredApiUrl.replace(/\/api\/?$/, '') : undefined;
};

const readStoredArray = (key) => {
  try {
    const stored = localStorage.getItem(key);
    const value = stored ? JSON.parse(stored) : [];
    return Array.isArray(value) ? value : [];
  } catch (error) {
    return [];
  }
};

const readStoredObject = (key) => {
  try {
    const stored = localStorage.getItem(key);
    const value = stored ? JSON.parse(stored) : {};
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch (error) {
    return {};
  }
};

const normalizeAutomatedScan = (data) => {
  if (!data?.results) {
    return data;
  }

  const results = data.results;
  const subdomainData = results.subdomains || {};
  const portData = results.ports || {};
  const vulnerabilityData = results.vulnerabilities || {};

  return {
    ...data,
    target: data.target || results.target,
    scan_type: 'automated',
    subdomains: Array.isArray(subdomainData)
      ? subdomainData
      : subdomainData.subdomains || [],
    scan_results: portData.scan_results || [],
    total_open_ports: portData.total_open_ports || 0,
    vulnerabilities: Array.isArray(vulnerabilityData)
      ? vulnerabilityData
      : vulnerabilityData.vulnerabilities || [],
    total_vulnerabilities: vulnerabilityData.total_vulnerabilities || 0,
    dns_records: results.dns?.dns_records || results.dns || {},
    ai_analysis: results.ai_analysis || {},
    timestamp: data.timestamp || new Date().toISOString(),
  };
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};

export const ScanProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [scanProgress, setScanProgress] = useState(null);
  const [learningMode, setLearningMode] = useState(true);
  const [user, setUser] = useState(null);
  const [reports, setReports] = useState(() => readStoredArray(REPORTS_STORAGE_KEY));
  const [apiSettings, setApiSettings] = useState(() => readStoredObject(API_SETTINGS_STORAGE_KEY));

  const persistReports = (nextReports) => {
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(nextReports));
  };

  useEffect(() => {
    const newSocket = io(getSocketUrl(), {
      path: '/socket.io',
      auth: { token: getApiAccessToken() || undefined },
    });
    setSocket(newSocket);

    newSocket.on('scan_status', (data) => {
      setScanProgress(data);
    });

    newSocket.on('scan_complete', (data) => {
      const normalizedResult = normalizeAutomatedScan(data);
      setCurrentScan(normalizedResult);
      setScanProgress(null);
      setScanHistory((previous) => [normalizedResult, ...previous]);
      apiService.saveScanResult(normalizedResult).catch((error) => {
        console.error('Failed to persist automated scan:', error);
      });
    });

    newSocket.on('scan_error', (data) => {
      console.error('Scan error:', data);
      setScanProgress({ status: 'error', message: data?.error || 'Automated scan failed' });
    });

    newSocket.on('connect_error', (error) => {
      console.error('Socket connection failed:', error);
      setScanProgress({ status: 'error', message: 'Unable to connect to the scan service' });
    });

    Promise.resolve(apiService.getScanHistory())
      .then((history) => setScanHistory(Array.isArray(history) ? history : []))
      .catch((error) => console.error('Failed to load scan history:', error));

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const loadScanHistory = async () => {
    try {
      const history = await apiService.getScanHistory();
      setScanHistory(Array.isArray(history) ? history : []);
    } catch (error) {
      console.error('Failed to load scan history:', error);
    }
  };

  const startScan = async (scanType, target, options = {}) => {
    try {
      setCurrentScan(null);
      setScanProgress({ status: 'starting', message: 'Initializing scan...' });

      let result;
      switch (scanType) {
        case 'subdomain':
          result = await apiService.scanSubdomains(target);
          break;
        case 'port':
          result = await apiService.scanPorts(target, options.portRange);
          break;
        case 'vulnerability':
          result = await apiService.scanVulnerabilities(target, options.scanType);
          break;
        case 'dns':
          result = await apiService.dnsEnumeration(target);
          break;
        case 'whois':
          result = await apiService.whoisLookup(target);
          break;
        case 'automated':
          if (!socket) {
            throw new Error('Scan connection is not ready');
          }
          socket.emit('start_automated_scan', {
            target,
            scan_types: options.scanTypes || ['subdomain', 'port', 'vuln'],
          });
          return;
        default:
          throw new Error(`Unsupported scan type: ${scanType}`);
      }

      await apiService.saveScanResult(result);
      setCurrentScan(result);
      setScanProgress(null);
      setScanHistory((previous) => [result, ...previous]);
      return result;
    } catch (error) {
      setScanProgress(null);
      throw error;
    }
  };

  const generateReport = async (scanData, format = 'html') => {
    try {
      const result = await apiService.generateReport(scanData, format);
      const findings = Array.isArray(scanData.vulnerabilities) ? scanData.vulnerabilities : [];
      const report = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        title: `Security report for ${scanData.target || scanData.domain || 'scan result'}`,
        description: `${format.toUpperCase()} report generated from the selected scan`,
        target: scanData.target || scanData.domain || 'Unknown',
        type: VULNERABILITY_SCAN_TYPES.has(scanData.scan_type) || Array.isArray(scanData.vulnerabilities)
          ? 'vulnerability_assessment'
          : 'reconnaissance',
        findings_count: findings.length,
        max_severity: findings.some((finding) => finding.severity === 'Critical')
          ? 'Critical'
          : findings.some((finding) => finding.severity === 'High')
            ? 'High'
            : findings.some((finding) => finding.severity === 'Medium')
              ? 'Medium'
              : findings.length > 0
                ? 'Low'
                : undefined,
        findings,
        created_at: result.timestamp || new Date().toISOString(),
        report_path: result.report_path,
        scan_data: scanData,
      };
      setReports((previous) => {
        const nextReports = [report, ...previous];
        persistReports(nextReports);
        return nextReports;
      });
      return result;
    } catch (error) {
      console.error('Report generation failed:', error);
      throw error;
    }
  };

  const deleteReport = async (reportId) => {
    setReports((previous) => {
      const nextReports = previous.filter((report) => report.id !== reportId);
      persistReports(nextReports);
      return nextReports;
    });
  };

  const exportReport = async (reportId, format) => {
    const report = reports.find((item) => item.id === reportId);
    if (!report) {
      throw new Error('Report not found');
    }
    const generated = await apiService.generateReport(report.scan_data, format);
    return apiService.downloadReport(generated.report_path);
  };

  const updateApiSettings = async (settings) => {
    const { api_access_token: accessToken, ...persistedSettings } = settings;
    const nextSettings = { ...apiSettings, ...persistedSettings };
    setApiSettings(nextSettings);
    localStorage.setItem(API_SETTINGS_STORAGE_KEY, JSON.stringify(nextSettings));
    const result = await apiService.updateUserSettings({ ...persistedSettings, api_access_token: accessToken });

    if (socket) {
      socket.auth = { token: getApiAccessToken() || undefined };
      socket.disconnect().connect();
    }
    return result;
  };

  const exportSettings = async () => ({
    ...readStoredObject('network-scanner-settings'),
    apiSettings,
    learningMode,
  });

  const importSettings = async (settings) => {
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
      throw new Error('Settings must be an object');
    }
    const importedApiSettings = settings.apiSettings || {};
    const nextSettings = { ...apiSettings, ...importedApiSettings };
    setApiSettings(nextSettings);
    localStorage.setItem(API_SETTINGS_STORAGE_KEY, JSON.stringify(nextSettings));
    if (typeof settings.learningMode === 'boolean') {
      setLearningMode(settings.learningMode);
    }
    return settings;
  };

  const chatWithAI = async (message, context = {}) => {
    try {
      return await apiService.chatWithAI(message, context);
    } catch (error) {
      console.error('AI chat failed:', error);
      throw error;
    }
  };

  const clearScanHistory = () => {
    setScanHistory([]);
    localStorage.setItem('scanHistory', JSON.stringify([]));
  };

  const removeScanFromHistory = (scanIndex) => {
    setScanHistory((previous) => {
      const nextHistory = previous.filter((_, index) => index !== scanIndex);
      localStorage.setItem('scanHistory', JSON.stringify(nextHistory));
      return nextHistory;
    });
  };

  const toggleLearningMode = () => {
    setLearningMode((previous) => !previous);
  };

  const value = {
    scanHistory,
    currentScan,
    scanProgress,
    learningMode,
    user,
    socket,
    reports,
    apiSettings,
    startScan,
    generateReport,
    deleteReport,
    exportReport,
    chatWithAI,
    clearScanHistory,
    removeScanFromHistory,
    toggleLearningMode,
    loadScanHistory,
    updateApiSettings,
    exportSettings,
    importSettings,
    setCurrentScan,
    setUser,
    setLearningMode,
  };

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
};
