import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import Scanner from './Scanner';
import { useScan } from '../context/ScanContext';

jest.mock('../context/ScanContext', () => ({
  useScan: jest.fn(),
}));

const renderScanner = (props = {}) => render(
  <ThemeProvider theme={createTheme()}>
    <Scanner showNotification={jest.fn()} {...props} />
  </ThemeProvider>
);

test('shows an explicit backend scan failure to the operator', async () => {
  const startScan = jest.fn().mockRejectedValue({ error: 'Port scan failed' });
  const showNotification = jest.fn();
  useScan.mockReturnValue({
    startScan,
    scanProgress: null,
    learningMode: false,
    toggleLearningMode: jest.fn(),
  });

  renderScanner({ showNotification });
  fireEvent.change(screen.getByLabelText('Target'), { target: { value: '127.0.0.1' } });
  fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

  await waitFor(() => {
    expect(showNotification).toHaveBeenCalledWith('Scan failed: Port scan failed', 'error');
  });
  expect(startScan).toHaveBeenCalledWith('subdomain', '127.0.0.1', {});
});
