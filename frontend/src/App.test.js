import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import App from './App';

let scannerProps;

jest.mock('./components/Scanner', () => (props) => {
  scannerProps = props;
  return <div data-testid="scanner-route" />;
});

jest.mock('socket.io-client', () => () => ({
  on: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
}));

jest.mock('./services/apiService', () => ({
  __esModule: true,
  default: {
    getScanHistory: jest.fn().mockResolvedValue([]),
  },
}));

test('routes Scanner with its showNotification contract', () => {
  render(
    <MemoryRouter initialEntries={['/scanner']}>
      <ThemeProvider theme={createTheme()}>
        <App />
      </ThemeProvider>
    </MemoryRouter>
  );

  expect(screen.getByTestId('scanner-route')).not.toBeNull();
  expect(typeof scannerProps.showNotification).toBe('function');
  expect(scannerProps.showAlert).toBeUndefined();
});
