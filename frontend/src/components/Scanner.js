import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Grid,
  Paper,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Settings as SettingsIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  Language as DnsIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const Scanner = ({ showNotification }) => {
  const { startScan, scanProgress, learningMode, toggleLearningMode } = useScan();
  const [activeTab, setActiveTab] = useState(0);
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [portRange, setPortRange] = useState('1-1000');
  const [selectedScanTypes, setSelectedScanTypes] = useState(['subdomain', 'port', 'vuln']);
  const [isScanning, setIsScanning] = useState(false);

  const handleStartScan = async () => {
    if (!target.trim()) {
      showNotification('Please enter a target', 'error');
      return;
    }

    try {
      setIsScanning(true);
      
      let scanTypeToUse;
      let options = {};
      
      switch (activeTab) {
        case 0: // Subdomain
          scanTypeToUse = 'subdomain';
          break;
        case 1: // Port Scan
          scanTypeToUse = 'port';
          options.portRange = portRange;
          break;
        case 2: // Vulnerability
          scanTypeToUse = 'vulnerability';
          options.scanType = scanType;
          break;
        case 3: // DNS
          scanTypeToUse = 'dns';
          break;
        case 4: // WHOIS
          scanTypeToUse = 'whois';
          break;
        case 5: // Automated
          scanTypeToUse = 'automated';
          options.scanTypes = selectedScanTypes;
          break;
        default:
          scanTypeToUse = 'subdomain';
      }

      await startScan(scanTypeToUse, target, options);
      showNotification(`${scanTypeToUse} scan started successfully`, 'success');
    } catch (error) {
      showNotification(`Scan failed: ${error.message}`, 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleScanTypeToggle = (type) => {
    setSelectedScanTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type)
        : [...prev, type]
    );
  };

  const tabLabels = ['Subdomain', 'Port Scan', 'Vulnerability', 'DNS', 'WHOIS', 'Automated'];

  const learningTips = {
    0: {
      title: "Subdomain Enumeration",
      content: "Discovers subdomains of your target domain. This helps identify additional attack surface and potentially interesting targets like admin panels, development environments, or forgotten services."
    },
    1: {
      title: "Port Scanning",
      content: "Identifies open network ports and running services. This reveals the network footprint and potential entry points. Common ports like 80 (HTTP), 443 (HTTPS), 22 (SSH) indicate specific services."
    },
    2: {
      title: "Vulnerability Assessment",
      content: "Analyzes discovered services for known vulnerabilities and security misconfigurations. This includes checking for outdated software, weak configurations, and common security issues."
    },
    3: {
      title: "DNS Enumeration",
      content: "Gathers DNS records (A, MX, NS, TXT, etc.) which can reveal infrastructure information, mail servers, and other technical details about the target domain."
    },
    4: {
      title: "WHOIS Lookup",
      content: "Retrieves domain registration information including registrar, creation date, nameservers, and sometimes contact information. Useful for reconnaissance and understanding domain ownership."
    },
    5: {
      title: "Automated Scanning",
      content: "Runs multiple scan types in sequence for comprehensive assessment. This provides a complete security overview but takes longer to complete."
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Security Scanner
        </Typography>
        <FormControlLabel
          control={<Switch checked={learningMode} onChange={toggleLearningMode} />}
          label="Learning Mode"
        />
      </Box>

      {/* Learning Mode Tip */}
      {learningMode && (
        <Card className="learning-tip fade-in" sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
              <InfoIcon className="tip-icon" />
              <Box>
                <Typography variant="h6" gutterBottom>
                  {learningTips[activeTab]?.title}
                </Typography>
                <Typography variant="body2">
                  {learningTips[activeTab]?.content}
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Target Input */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={3} alignItems="center">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or 192.168.1.1"
                variant="outlined"
                disabled={isScanning}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <Button
                fullWidth
                variant="contained"
                size="large"
                startIcon={isScanning ? <StopIcon /> : <PlayIcon />}
                onClick={handleStartScan}
                disabled={isScanning || !target.trim()}
                sx={{ height: 56 }}
              >
                {isScanning ? 'Scanning...' : 'Start Scan'}
              </Button>
            </Grid>
            <Grid item xs={12} md={3}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<SettingsIcon />}
                sx={{ height: 56 }}
                disabled={isScanning}
              >
                Advanced Options
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Scan Progress */}
      {scanProgress && (
        <Card sx={{ mb: 3 }} className="fade-in">
          <CardContent>
            <Typography variant="h6" gutterBottom>
              {scanProgress.status === 'running' ? 'Scanning in Progress' : 'Scan Status'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {scanProgress.message}
            </Typography>
            <LinearProgress 
              className={scanProgress.status === 'running' ? 'pulsing' : ''} 
              variant={scanProgress.status === 'running' ? 'indeterminate' : 'determinate'}
              value={scanProgress.status === 'completed' ? 100 : undefined}
            />
          </CardContent>
        </Card>
      )}

      {/* Scan Types */}
      <Card>
        <CardContent>
          <Tabs 
            value={activeTab} 
            onChange={(e, val) => setActiveTab(val)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ mb: 3 }}
          >
            {tabLabels.map((label, index) => (
              <Tab key={index} label={label} />
            ))}
          </Tabs>

          {/* Subdomain Enumeration */}
          {activeTab === 0 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Subdomain Enumeration
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Discover subdomains using multiple techniques including brute force, certificate transparency, and DNS enumeration.
              </Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                This scan will attempt to find subdomains of your target domain. Results may include development environments, admin panels, and other services.
              </Alert>
            </Box>
          )}

          {/* Port Scanning */}
          {activeTab === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Port Scanning
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Identify open ports and running services on the target system.
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Port Range</InputLabel>
                <Select
                  value={portRange}
                  onChange={(e) => setPortRange(e.target.value)}
                  label="Port Range"
                >
                  <MenuItem value="1-1000">Top 1000 ports</MenuItem>
                  <MenuItem value="1-65535">All ports (slow)</MenuItem>
                  <MenuItem value="21,22,23,25,53,80,110,143,443,993,995">Common ports</MenuItem>
                  <MenuItem value="80,443,8080,8443">Web ports only</MenuItem>
                </Select>
              </FormControl>
              <Alert severity="warning">
                Port scanning may be detected by intrusion detection systems. Ensure you have permission to scan the target.
              </Alert>
            </Box>
          )}

          {/* Vulnerability Scanning */}
          {activeTab === 2 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Vulnerability Assessment
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Analyze the target for known vulnerabilities and security misconfigurations.
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  label="Scan Type"
                >
                  <MenuItem value="basic">Basic (Quick)</MenuItem>
                  <MenuItem value="web">Web Application</MenuItem>
                  <MenuItem value="network">Network Services</MenuItem>
                  <MenuItem value="comprehensive">Comprehensive (Slow)</MenuItem>
                </Select>
              </FormControl>
              <Alert severity="error">
                Vulnerability scanning may cause service disruption. Only scan systems you own or have explicit permission to test.
              </Alert>
            </Box>
          )}

          {/* DNS Enumeration */}
          {activeTab === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                DNS Enumeration
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Gather DNS records to understand the domain infrastructure.
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="A Records" secondary="IPv4 addresses" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="MX Records" secondary="Mail servers" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="NS Records" secondary="Name servers" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="TXT Records" secondary="Text records (SPF, DMARC, etc.)" />
                </ListItem>
              </List>
            </Box>
          )}

          {/* WHOIS Lookup */}
          {activeTab === 4 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                WHOIS Lookup
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Retrieve domain registration information and ownership details.
              </Typography>
              <Alert severity="info">
                WHOIS data includes registrar information, creation date, expiration date, and sometimes contact details.
              </Alert>
            </Box>
          )}

          {/* Automated Scanning */}
          {activeTab === 5 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Automated Comprehensive Scan
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Run multiple scan types automatically for complete assessment.
              </Typography>
              
              <Typography variant="subtitle1" sx={{ mb: 2 }}>
                Select scan types to include:
              </Typography>
              
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                {[
                  { id: 'subdomain', label: 'Subdomain Enumeration', icon: <SecurityIcon /> },
                  { id: 'port', label: 'Port Scanning', icon: <SecurityIcon /> },
                  { id: 'vuln', label: 'Vulnerability Assessment', icon: <BugIcon /> },
                  { id: 'dns', label: 'DNS Enumeration', icon: <DnsIcon /> },
                ].map(({ id, label, icon }) => (
                  <Chip
                    key={id}
                    icon={icon}
                    label={label}
                    onClick={() => handleScanTypeToggle(id)}
                    color={selectedScanTypes.includes(id) ? 'primary' : 'default'}
                    variant={selectedScanTypes.includes(id) ? 'filled' : 'outlined'}
                  />
                ))}
              </Box>
              
              <Alert severity="warning">
                Automated scans may take 10-30 minutes depending on the target size and selected scan types.
              </Alert>
            </Box>
          )}

          {/* Advanced Options Accordion */}
          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>Advanced Options</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Timeout (seconds)"
                    type="number"
                    defaultValue={30}
                    variant="outlined"
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Threads"
                    type="number"
                    defaultValue={10}
                    variant="outlined"
                    size="small"
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={<Switch defaultChecked />}
                    label="Enable AI Analysis"
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={<Switch />}
                    label="Aggressive Mode (may be detected)"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </CardContent>
      </Card>
    </Box>
  );
};

export default Scanner;
