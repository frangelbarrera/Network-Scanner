import React, { useEffect, useState } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Grid,
  IconButton,
  MenuItem,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import {
  Api as ApiIcon,
  ExpandMore as ExpandMoreIcon,
  Save as SaveIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';
import { getApiAccessToken } from '../services/apiService';

const SETTINGS_STORAGE_KEY = 'network-scanner-settings';
const defaultSettings = {
  learningMode: true,
  autoSave: true,
  notifications: true,
  theme: 'dark',
  defaultFormat: 'pdf',
  includeRawData: false,
  companyName: '',
  logoUrl: '',
};

const readStoredSettings = () => {
  try {
    const stored = localStorage.getItem(SETTINGS_STORAGE_KEY);
    const parsed = stored ? JSON.parse(stored) : {};
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    return {};
  }
};

const Settings = ({ showNotification }) => {
  const {
    learningMode,
    setLearningMode,
    updateApiSettings,
    exportSettings,
    importSettings,
  } = useScan();

  const [settings, setSettings] = useState(() => ({ ...defaultSettings, ...readStoredSettings() }));
  const [accessToken, setAccessToken] = useState('');
  const [tokenConfigured, setTokenConfigured] = useState(Boolean(getApiAccessToken()));
  const [showAccessToken, setShowAccessToken] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [importData, setImportData] = useState('');

  useEffect(() => {
    setSettings((current) => ({ ...current, learningMode }));
  }, [learningMode]);

  const handleSettingChange = (key, value) => {
    setSettings((current) => ({ ...current, [key]: value }));
    if (key === 'learningMode') {
      setLearningMode(value);
    }
  };

  const handleSave = async () => {
    setIsLoading(true);
    try {
      localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
      await updateApiSettings({ api_access_token: accessToken });
      setLearningMode(settings.learningMode);
      setTokenConfigured(Boolean(getApiAccessToken()));
      setAccessToken('');
      showNotification('Settings saved successfully', 'success');
    } catch (error) {
      showNotification('Failed to save settings', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = async () => {
    try {
      const exportData = await exportSettings();
      const blob = new Blob([JSON.stringify({ ...settings, ...exportData }, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'network-scanner-settings.json';
      anchor.click();
      URL.revokeObjectURL(url);
      showNotification('Settings exported successfully', 'success');
    } catch (error) {
      showNotification('Failed to export settings', 'error');
    }
  };

  const handleImport = async () => {
    try {
      const data = JSON.parse(importData);
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('Settings must be an object');
      }
      const { api_access_token: ignoredToken, ...importedSettings } = data;
      await importSettings(importedSettings);
      setSettings((current) => ({ ...current, ...importedSettings }));
      if (typeof importedSettings.learningMode === 'boolean') {
        setLearningMode(importedSettings.learningMode);
      }
      setImportDialogOpen(false);
      setImportData('');
      showNotification('Settings imported successfully', 'success');
    } catch (error) {
      showNotification('Failed to import settings. Check the format.', 'error');
    }
  };

  const resetToDefaults = () => {
    setSettings(defaultSettings);
    setLearningMode(defaultSettings.learningMode);
    showNotification('Settings reset to defaults. Save to keep these changes.', 'info');
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Settings
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button variant="outlined" onClick={handleExport}>Export Settings</Button>
          <Button variant="outlined" onClick={() => setImportDialogOpen(true)}>Import Settings</Button>
          <Button variant="contained" startIcon={<SaveIcon />} onClick={handleSave} disabled={isLoading}>
            Save Changes
          </Button>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SettingsIcon />
                <Typography variant="h6">General Settings</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={<Switch checked={settings.learningMode} onChange={(event) => handleSettingChange('learningMode', event.target.checked)} />}
                    label="Learning Mode"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Show educational explanations alongside scan results.
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={<Switch checked={settings.autoSave} onChange={(event) => handleSettingChange('autoSave', event.target.checked)} />}
                    label="Auto-save Results"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Keep scan history in this browser.
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={<Switch checked={settings.notifications} onChange={(event) => handleSettingChange('notifications', event.target.checked)} />}
                    label="Enable Notifications"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField select fullWidth label="Theme" value={settings.theme} onChange={(event) => handleSettingChange('theme', event.target.value)} size="small">
                    <MenuItem value="light">Light</MenuItem>
                    <MenuItem value="dark">Dark</MenuItem>
                    <MenuItem value="auto">Auto</MenuItem>
                  </TextField>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon />
                <Typography variant="h6">Service Access</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="info" sx={{ mb: 2 }}>
                The API access token is kept only for this browser session and is never included in exported settings. AI provider credentials are configured server-side by the operator.
              </Alert>
              <TextField
                fullWidth
                label="API Access Token"
                type={showAccessToken ? 'text' : 'password'}
                value={accessToken}
                onChange={(event) => setAccessToken(event.target.value)}
                size="small"
                InputProps={{
                  endAdornment: (
                    <IconButton onClick={() => setShowAccessToken((visible) => !visible)} edge="end">
                      {showAccessToken ? <VisibilityOffIcon /> : <VisibilityIcon />}
                    </IconButton>
                  ),
                }}
                helperText="Leave empty and save to clear the token from this browser session."
              />
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ApiIcon />
                <Typography variant="h6">Report Defaults</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField select fullWidth label="Default Report Format" value={settings.defaultFormat} onChange={(event) => handleSettingChange('defaultFormat', event.target.value)} size="small">
                    <MenuItem value="pdf">PDF</MenuItem>
                    <MenuItem value="html">HTML</MenuItem>
                  </TextField>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={<Switch checked={settings.includeRawData} onChange={(event) => handleSettingChange('includeRawData', event.target.checked)} />}
                    label="Include Raw Data"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField fullWidth label="Company Name" value={settings.companyName} onChange={(event) => handleSettingChange('companyName', event.target.value)} size="small" placeholder="Your Organization" />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField fullWidth label="Logo URL" value={settings.logoUrl} onChange={(event) => handleSettingChange('logoUrl', event.target.value)} size="small" placeholder="https://example.com/logo.png" />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Box sx={{ mt: 2 }}>
            <Button variant="outlined" color="warning" onClick={resetToDefaults}>Reset to Defaults</Button>
          </Box>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card sx={{ position: 'sticky', top: 20 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>Configuration Status</Typography>
              <Alert severity={tokenConfigured ? 'success' : 'warning'} sx={{ mb: 2 }}>
                {tokenConfigured ? 'An API token is active for this browser session.' : 'No API token is configured for this browser session.'}
              </Alert>
              <Typography variant="body2" color="text.secondary" paragraph>
                Preferences are local to this browser. Service credentials and AI provider configuration are controlled by the deployment environment.
              </Typography>
              <Button fullWidth variant="contained" startIcon={<SaveIcon />} onClick={handleSave} disabled={isLoading}>
                Save All Settings
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Dialog open={importDialogOpen} onClose={() => setImportDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Import Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Paste previously exported preference JSON. Access tokens are intentionally ignored.
          </Typography>
          <TextField fullWidth multiline rows={10} value={importData} onChange={(event) => setImportData(event.target.value)} placeholder='{"learningMode": true, ...}' variant="outlined" />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleImport} disabled={!importData.trim()}>Import</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Settings;
