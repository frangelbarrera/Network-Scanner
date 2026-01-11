import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Divider,
  Alert,
  Grid,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  MenuItem,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  ExpandMore as ExpandMoreIcon,
  Api as ApiIcon,
  Notifications as NotificationsIcon,
  Settings as SettingsIcon,
  StorageIcon,
  NetworkCheck as NetworkIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const Settings = ({ showNotification }) => {
  const { 
    learningMode, 
    setLearningMode, 
    apiSettings, 
    updateApiSettings,
    exportSettings,
    importSettings 
  } = useScan();

  const [settings, setSettings] = useState({
    // General Settings
    learningMode: learningMode,
    autoSave: true,
    notifications: true,
    theme: 'light',
    
    // API Settings
    openaiApiKey: '',
    openaiModel: 'gpt-3.5-turbo',
    maxTokens: 1000,
    
    // Scanning Settings
    defaultTimeout: 30,
    maxThreads: 10,
    retryAttempts: 3,
    enableDeepScan: false,
    
    // Report Settings
    defaultFormat: 'pdf',
    includeRawData: false,
    logoUrl: '',
    companyName: '',
    
    // Security Settings
    sessionTimeout: 30,
    requireApiKey: false,
    enableAuditLog: true,
    
    // Advanced Settings
    debugMode: false,
    verboseLogging: false,
    cacheResults: true,
    cacheExpiry: 24
  });

  const [showApiKey, setShowApiKey] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [importData, setImportData] = useState('');

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      // Load settings from backend or localStorage
      const savedSettings = localStorage.getItem('secscanx-settings');
      if (savedSettings) {
        const parsed = JSON.parse(savedSettings);
        setSettings(prev => ({ ...prev, ...parsed }));
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  };

  const handleSettingChange = (key, value) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));

    // Apply certain settings immediately
    if (key === 'learningMode') {
      setLearningMode(value);
    }
  };

  const handleSave = async () => {
    setIsLoading(true);
    try {
      // Save to localStorage and backend
      localStorage.setItem('secscanx-settings', JSON.stringify(settings));
      
      // Update API settings if they've changed
      if (settings.openaiApiKey || settings.openaiModel) {
        await updateApiSettings({
          openai_api_key: settings.openaiApiKey,
          model: settings.openaiModel,
          max_tokens: settings.maxTokens
        });
      }

      // Apply other settings
      setLearningMode(settings.learningMode);
      
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
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'secscanx-settings.json';
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Settings exported successfully', 'success');
    } catch (error) {
      showNotification('Failed to export settings', 'error');
    }
  };

  const handleImport = async () => {
    try {
      const data = JSON.parse(importData);
      await importSettings(data);
      setSettings(prev => ({ ...prev, ...data }));
      setImportDialogOpen(false);
      setImportData('');
      showNotification('Settings imported successfully', 'success');
    } catch (error) {
      showNotification('Failed to import settings. Check the format.', 'error');
    }
  };

  const resetToDefaults = () => {
    const defaultSettings = {
      learningMode: true,
      autoSave: true,
      notifications: true,
      theme: 'light',
      openaiApiKey: '',
      openaiModel: 'gpt-3.5-turbo',
      maxTokens: 1000,
      defaultTimeout: 30,
      maxThreads: 10,
      retryAttempts: 3,
      enableDeepScan: false,
      defaultFormat: 'pdf',
      includeRawData: false,
      logoUrl: '',
      companyName: '',
      sessionTimeout: 30,
      requireApiKey: false,
      enableAuditLog: true,
      debugMode: false,
      verboseLogging: false,
      cacheResults: true,
      cacheExpiry: 24
    };
    setSettings(defaultSettings);
    showNotification('Settings reset to defaults', 'info');
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          ⚙️ Settings
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button variant="outlined" onClick={handleExport}>
            Export Settings
          </Button>
          <Button variant="outlined" onClick={() => setImportDialogOpen(true)}>
            Import Settings
          </Button>
          <Button 
            variant="contained" 
            startIcon={<SaveIcon />}
            onClick={handleSave}
            disabled={isLoading}
          >
            Save Changes
          </Button>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          {/* General Settings */}
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
                    control={
                      <Switch
                        checked={settings.learningMode}
                        onChange={(e) => handleSettingChange('learningMode', e.target.checked)}
                      />
                    }
                    label="Learning Mode"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Provides educational explanations and beginner-friendly guidance
                  </Typography>
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.autoSave}
                        onChange={(e) => handleSettingChange('autoSave', e.target.checked)}
                      />
                    }
                    label="Auto-save Results"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Automatically save scan results to database
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications}
                        onChange={(e) => handleSettingChange('notifications', e.target.checked)}
                      />
                    }
                    label="Enable Notifications"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Show desktop notifications for completed scans
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    select
                    fullWidth
                    label="Theme"
                    value={settings.theme}
                    onChange={(e) => handleSettingChange('theme', e.target.value)}
                    size="small"
                  >
                    <MenuItem value="light">Light</MenuItem>
                    <MenuItem value="dark">Dark</MenuItem>
                    <MenuItem value="auto">Auto</MenuItem>
                  </TextField>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* AI Settings */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ApiIcon />
                <Typography variant="h6">AI Assistant Settings</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="OpenAI API Key"
                    type={showApiKey ? 'text' : 'password'}
                    value={settings.openaiApiKey}
                    onChange={(e) => handleSettingChange('openaiApiKey', e.target.value)}
                    size="small"
                    InputProps={{
                      endAdornment: (
                        <IconButton
                          onClick={() => setShowApiKey(!showApiKey)}
                          edge="end"
                        >
                          {showApiKey ? <VisibilityOffIcon /> : <VisibilityIcon />}
                        </IconButton>
                      )
                    }}
                    helperText="Required for AI assistant functionality"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    select
                    fullWidth
                    label="AI Model"
                    value={settings.openaiModel}
                    onChange={(e) => handleSettingChange('openaiModel', e.target.value)}
                    size="small"
                  >
                    <MenuItem value="gpt-3.5-turbo">GPT-3.5 Turbo</MenuItem>
                    <MenuItem value="gpt-4">GPT-4</MenuItem>
                    <MenuItem value="gpt-4-turbo">GPT-4 Turbo</MenuItem>
                  </TextField>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Max Tokens"
                    type="number"
                    value={settings.maxTokens}
                    onChange={(e) => handleSettingChange('maxTokens', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 100, max: 4000 }}
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Scanning Settings */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <NetworkIcon />
                <Typography variant="h6">Scanning Settings</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={4}>
                  <TextField
                    fullWidth
                    label="Default Timeout (seconds)"
                    type="number"
                    value={settings.defaultTimeout}
                    onChange={(e) => handleSettingChange('defaultTimeout', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 5, max: 300 }}
                  />
                </Grid>

                <Grid item xs={12} sm={4}>
                  <TextField
                    fullWidth
                    label="Max Threads"
                    type="number"
                    value={settings.maxThreads}
                    onChange={(e) => handleSettingChange('maxThreads', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 1, max: 50 }}
                  />
                </Grid>

                <Grid item xs={12} sm={4}>
                  <TextField
                    fullWidth
                    label="Retry Attempts"
                    type="number"
                    value={settings.retryAttempts}
                    onChange={(e) => handleSettingChange('retryAttempts', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 0, max: 10 }}
                  />
                </Grid>

                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.enableDeepScan}
                        onChange={(e) => handleSettingChange('enableDeepScan', e.target.checked)}
                      />
                    }
                    label="Enable Deep Scanning"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Performs more thorough scans but takes longer
                  </Typography>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Report Settings */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <StorageIcon />
                <Typography variant="h6">Report Settings</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    select
                    fullWidth
                    label="Default Report Format"
                    value={settings.defaultFormat}
                    onChange={(e) => handleSettingChange('defaultFormat', e.target.value)}
                    size="small"
                  >
                    <MenuItem value="pdf">PDF</MenuItem>
                    <MenuItem value="html">HTML</MenuItem>
                    <MenuItem value="json">JSON</MenuItem>
                  </TextField>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.includeRawData}
                        onChange={(e) => handleSettingChange('includeRawData', e.target.checked)}
                      />
                    }
                    label="Include Raw Data"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Company Name"
                    value={settings.companyName}
                    onChange={(e) => handleSettingChange('companyName', e.target.value)}
                    size="small"
                    placeholder="Your Organization"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Logo URL"
                    value={settings.logoUrl}
                    onChange={(e) => handleSettingChange('logoUrl', e.target.value)}
                    size="small"
                    placeholder="https://example.com/logo.png"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Security Settings */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon />
                <Typography variant="h6">Security Settings</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Session Timeout (minutes)"
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) => handleSettingChange('sessionTimeout', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 5, max: 480 }}
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.requireApiKey}
                        onChange={(e) => handleSettingChange('requireApiKey', e.target.checked)}
                      />
                    }
                    label="Require API Key"
                  />
                </Grid>

                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.enableAuditLog}
                        onChange={(e) => handleSettingChange('enableAuditLog', e.target.checked)}
                      />
                    }
                    label="Enable Audit Logging"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Track all user actions and system events
                  </Typography>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Advanced Settings */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">🔧 Advanced Settings</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.debugMode}
                        onChange={(e) => handleSettingChange('debugMode', e.target.checked)}
                      />
                    }
                    label="Debug Mode"
                  />
                  <Typography variant="caption" display="block" color="text.secondary">
                    Enable detailed debugging information
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.verboseLogging}
                        onChange={(e) => handleSettingChange('verboseLogging', e.target.checked)}
                      />
                    }
                    label="Verbose Logging"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.cacheResults}
                        onChange={(e) => handleSettingChange('cacheResults', e.target.checked)}
                      />
                    }
                    label="Cache Results"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Cache Expiry (hours)"
                    type="number"
                    value={settings.cacheExpiry}
                    onChange={(e) => handleSettingChange('cacheExpiry', parseInt(e.target.value))}
                    size="small"
                    inputProps={{ min: 1, max: 168 }}
                  />
                </Grid>
              </Grid>

              <Box sx={{ mt: 2 }}>
                <Button
                  variant="outlined"
                  color="warning"
                  onClick={resetToDefaults}
                >
                  Reset to Defaults
                </Button>
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Settings Summary Sidebar */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ position: 'sticky', top: 20 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Configuration Status
              </Typography>
              
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="Learning Mode"
                    secondary={settings.learningMode ? 'Enabled' : 'Disabled'}
                  />
                  <Chip 
                    size="small" 
                    label={settings.learningMode ? 'ON' : 'OFF'}
                    color={settings.learningMode ? 'success' : 'default'}
                  />
                </ListItem>

                <ListItem>
                  <ListItemText 
                    primary="AI Assistant"
                    secondary={settings.openaiApiKey ? 'Configured' : 'Not configured'}
                  />
                  <Chip 
                    size="small" 
                    label={settings.openaiApiKey ? 'READY' : 'SETUP'}
                    color={settings.openaiApiKey ? 'success' : 'warning'}
                  />
                </ListItem>

                <ListItem>
                  <ListItemText 
                    primary="Auto-save"
                    secondary={settings.autoSave ? 'Enabled' : 'Disabled'}
                  />
                  <Chip 
                    size="small" 
                    label={settings.autoSave ? 'ON' : 'OFF'}
                    color={settings.autoSave ? 'success' : 'default'}
                  />
                </ListItem>

                <ListItem>
                  <ListItemText 
                    primary="Security"
                    secondary={`${settings.sessionTimeout}min timeout`}
                  />
                  <Chip 
                    size="small" 
                    label="SECURE"
                    color="info"
                  />
                </ListItem>
              </List>

              <Divider sx={{ my: 2 }} />

              <Alert severity="info" sx={{ mb: 2 }}>
                Don't forget to save your changes!
              </Alert>

              <Button
                fullWidth
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSave}
                disabled={isLoading}
              >
                Save All Settings
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Import Settings Dialog */}
      <Dialog 
        open={importDialogOpen} 
        onClose={() => setImportDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Import Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Paste your exported settings JSON here:
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={10}
            value={importData}
            onChange={(e) => setImportData(e.target.value)}
            placeholder='{"learningMode": true, ...}'
            variant="outlined"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleImport}
            disabled={!importData.trim()}
          >
            Import
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Settings;
