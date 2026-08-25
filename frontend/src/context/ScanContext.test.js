import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { ScanProvider, useScan } from './ScanContext';
import apiService from '../services/apiService';

let mockSocketHandlers;

jest.mock('socket.io-client', () => () => {
  mockSocketHandlers = {};
  return {
    on: jest.fn((event, handler) => {
      mockSocketHandlers[event] = handler;
    }),
    disconnect: jest.fn(),
    emit: jest.fn(),
  };
});

jest.mock('../services/apiService', () => ({
  __esModule: true,
  getApiAccessToken: jest.fn(() => null),
  default: {
    getScanHistory: jest.fn(),
    saveScanResult: jest.fn(),
    scanPorts: jest.fn(),
    generateReport: jest.fn(),
    downloadReport: jest.fn(),
    updateUserSettings: jest.fn(),
    chatWithAI: jest.fn(),
  },
}));

let contextValue;

function ContextProbe() {
  contextValue = useScan();
  return null;
}

describe('ScanContext compatibility contracts', () => {
  beforeEach(() => {
    contextValue = undefined;
    localStorage.clear();
    apiService.getScanHistory.mockResolvedValue([]);
    apiService.saveScanResult.mockResolvedValue({});
    apiService.scanPorts.mockResolvedValue({ target: '127.0.0.1', scan_results: [] });
  });

  test('exposes the report and settings members consumed by existing screens', async () => {
    render(
      <ScanProvider>
        <ContextProbe />
      </ScanProvider>
    );

    await waitFor(() => expect(contextValue).toBeDefined());
    ['reports', 'deleteReport', 'exportReport', 'setLearningMode', 'apiSettings', 'updateApiSettings', 'exportSettings', 'importSettings'].forEach((key) => {
      expect(contextValue[key]).toBeDefined();
    });
  });

  test('normalizes legacy automated socket payloads for Results consumers', async () => {
    render(
      <ScanProvider>
        <ContextProbe />
      </ScanProvider>
    );

    await waitFor(() => expect(mockSocketHandlers.scan_complete).toBeDefined());
    act(() => {
      mockSocketHandlers.scan_complete({
        target: '127.0.0.1',
        results: {
          subdomains: { subdomains: ['api.example.test'] },
          ports: { scan_results: [{ host: '127.0.0.1', open_ports: [] }], total_open_ports: 0 },
          vulnerabilities: { vulnerabilities: [{ title: 'simulated', severity: 'Low' }] },
          ai_analysis: { assessment: 'simulated' },
        },
      });
    });

    await waitFor(() => expect(contextValue.currentScan.scan_type).toBe('automated'));
    expect(contextValue.currentScan.subdomains).toEqual(['api.example.test']);
    expect(contextValue.currentScan.vulnerabilities).toHaveLength(1);
    expect(contextValue.currentScan.scan_results).toHaveLength(1);
  });

  test('persists a successful scan before adding it to the visible history', async () => {
    render(
      <ScanProvider>
        <ContextProbe />
      </ScanProvider>
    );

    await waitFor(() => expect(contextValue).toBeDefined());
    await act(async () => {
      await contextValue.startScan('port', '127.0.0.1', { portRange: '443' });
    });

    expect(apiService.saveScanResult).toHaveBeenCalledWith({ target: '127.0.0.1', scan_results: [] });
  });
});
