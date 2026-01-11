import React, { createContext, useContext, useState, useEffect } from 'react';
import io from 'socket.io-client';
import apiService from '../services/apiService';

const ScanContext = createContext();

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

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
    setSocket(newSocket);

    // Socket event listeners
    newSocket.on('scan_status', (data) => {
      setScanProgress(data);
    });

    newSocket.on('scan_complete', (data) => {
      setCurrentScan(data);
      setScanProgress(null);
      // Add to scan history
      setScanHistory(prev => [data, ...prev]);
    });

    newSocket.on('scan_error', (data) => {
      console.error('Scan error:', data);
      setScanProgress(null);
    });

    // Load scan history on mount
    loadScanHistory();

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const loadScanHistory = async () => {
    try {
      const history = await apiService.getScanHistory();
      setScanHistory(history);
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
          // Use socket for automated scans
          if (socket) {
            socket.emit('start_automated_scan', {
              target,
              scan_types: options.scanTypes || ['subdomain', 'port', 'vuln']
            });
          }
          return;
        default:
          throw new Error(`Unsupported scan type: ${scanType}`);
      }

      setCurrentScan(result);
      setScanProgress(null);
      setScanHistory(prev => [result, ...prev]);
      return result;
    } catch (error) {
      setScanProgress(null);
      throw error;
    }
  };

  const generateReport = async (scanData, format = 'html') => {
    try {
      const result = await apiService.generateReport(scanData, format);
      return result;
    } catch (error) {
      console.error('Report generation failed:', error);
      throw error;
    }
  };

  const chatWithAI = async (message, context = {}) => {
    try {
      const result = await apiService.chatWithAI(message, context);
      return result;
    } catch (error) {
      console.error('AI chat failed:', error);
      throw error;
    }
  };

  const clearScanHistory = () => {
    setScanHistory([]);
  };

  const removeScanFromHistory = (scanIndex) => {
    setScanHistory(prev => prev.filter((_, index) => index !== scanIndex));
  };

  const toggleLearningMode = () => {
    setLearningMode(prev => !prev);
  };

  const value = {
    // State
    scanHistory,
    currentScan,
    scanProgress,
    learningMode,
    user,
    socket,

    // Actions
    startScan,
    generateReport,
    chatWithAI,
    clearScanHistory,
    removeScanFromHistory,
    toggleLearningMode,
    loadScanHistory,

    // Setters
    setCurrentScan,
    setUser,
  };

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
};
