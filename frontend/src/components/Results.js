import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
  Chip,
  Button,
  Grid,
  Alert,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  FilterList as FilterIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugIcon,
  Security as SecurityIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';
import ReactJson from 'react-json-view';

const Results = ({ showNotification }) => {
  const { scanHistory, removeScanFromHistory, generateReport } = useScan();
  const [selectedResult, setSelectedResult] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const handleViewResult = (result, index) => {
    setSelectedResult({ ...result, index });
    setDialogOpen(true);
  };

  const handleDeleteResult = (index) => {
    removeScanFromHistory(index);
    showNotification('Scan result deleted', 'info');
  };

  const handleGenerateReport = async (result) => {
    try {
      const reportPath = await generateReport(result, 'html');
      showNotification(`Report generated: ${reportPath}`, 'success');
    } catch (error) {
      showNotification(`Report generation failed: ${error.message}`, 'error');
    }
  };

  const filteredResults = scanHistory.filter(result => {
    const matchesFilter = filter === 'all' || 
      (result.scan_type && result.scan_type.toLowerCase().includes(filter.toLowerCase()));
    
    const matchesSearch = !searchTerm || 
      (result.domain && result.domain.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (result.target && result.target.toLowerCase().includes(searchTerm.toLowerCase()));
    
    return matchesFilter && matchesSearch;
  });

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'error',
      'High': 'error',
      'Medium': 'warning',
      'Low': 'success'
    };
    return colors[severity] || 'default';
  };

  const renderVulnerabilities = (vulnerabilities) => {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return <Typography variant="body2">No vulnerabilities found</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          Vulnerabilities ({vulnerabilities.length})
        </Typography>
        {vulnerabilities.map((vuln, index) => (
          <Card key={index} className={`vulnerability-card ${vuln.severity?.toLowerCase()}`} sx={{ mb: 1 }}>
            <CardContent sx={{ py: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                    {vuln.title || 'Unknown Vulnerability'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {vuln.description || 'No description available'}
                  </Typography>
                  <Typography variant="caption" display="block">
                    <strong>Type:</strong> {vuln.type || 'Unknown'} | 
                    <strong> Port:</strong> {vuln.port || 'N/A'} | 
                    <strong> Service:</strong> {vuln.service || 'N/A'}
                  </Typography>
                  {vuln.recommendation && (
                    <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                      <strong>Recommendation:</strong> {vuln.recommendation}
                    </Typography>
                  )}
                </Box>
                <Chip
                  label={vuln.severity || 'Low'}
                  color={getSeverityColor(vuln.severity)}
                  size="small"
                  className={`severity-chip ${vuln.severity?.toLowerCase() || 'low'}`}
                />
              </Box>
            </CardContent>
          </Card>
        ))}
      </Box>
    );
  };

  const renderSubdomains = (subdomains) => {
    if (!subdomains || subdomains.length === 0) {
      return <Typography variant="body2">No subdomains found</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          Subdomains ({subdomains.length})
        </Typography>
        <div className="subdomain-grid">
          {subdomains.slice(0, 20).map((subdomain, index) => (
            <div key={index} className="subdomain-item">
              {subdomain}
            </div>
          ))}
          {subdomains.length > 20 && (
            <div className="subdomain-item" style={{ fontStyle: 'italic' }}>
              ... and {subdomains.length - 20} more
            </div>
          )}
        </div>
      </Box>
    );
  };

  const renderPortScan = (scanResults) => {
    if (!scanResults || scanResults.length === 0) {
      return <Typography variant="body2">No port scan results</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          Port Scan Results
        </Typography>
        {scanResults.map((host, hostIndex) => (
          <Box key={hostIndex} sx={{ mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
              Host: {host.host} ({host.state})
            </Typography>
            {host.open_ports && host.open_ports.length > 0 ? (
              <Box sx={{ ml: 2 }}>
                {host.open_ports.map((port, portIndex) => (
                  <Typography key={portIndex} variant="body2" component="div">
                    • Port {port.port}/{port.protocol} - {port.service} {port.version}
                  </Typography>
                ))}
              </Box>
            ) : (
              <Typography variant="body2" sx={{ ml: 2, fontStyle: 'italic' }}>
                No open ports found
              </Typography>
            )}
          </Box>
        ))}
      </Box>
    );
  };

  const renderAIAnalysis = (aiAnalysis) => {
    if (!aiAnalysis) return null;

    return (
      <Box className="ai-analysis" sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          🤖 AI Security Analysis
        </Typography>
        
        {aiAnalysis.assessment && (
          <Typography variant="body1" sx={{ mb: 2 }}>
            <strong>Assessment:</strong> {aiAnalysis.assessment}
          </Typography>
        )}
        
        {aiAnalysis.risk_level && (
          <Typography variant="body1" sx={{ mb: 2 }}>
            <strong>Risk Level:</strong> {aiAnalysis.risk_level}
          </Typography>
        )}
        
        {aiAnalysis.recommendations && Array.isArray(aiAnalysis.recommendations) && (
          <Box>
            <Typography variant="body1" sx={{ fontWeight: 'bold', mb: 1 }}>
              Recommendations:
            </Typography>
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {aiAnalysis.recommendations.map((rec, index) => (
                <li key={index}>
                  <Typography variant="body2">{rec}</Typography>
                </li>
              ))}
            </ul>
          </Box>
        )}
      </Box>
    );
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Scan Results
        </Typography>
      </Box>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={6} md={4}>
              <TextField
                fullWidth
                label="Search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by target or domain..."
                variant="outlined"
                size="small"
              />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel>Filter by Type</InputLabel>
                <Select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  label="Filter by Type"
                >
                  <MenuItem value="all">All Scans</MenuItem>
                  <MenuItem value="subdomain">Subdomain</MenuItem>
                  <MenuItem value="port">Port Scan</MenuItem>
                  <MenuItem value="vulnerability">Vulnerability</MenuItem>
                  <MenuItem value="dns">DNS</MenuItem>
                  <MenuItem value="whois">WHOIS</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={12} md={4}>
              <Typography variant="body2" color="text.secondary">
                {filteredResults.length} of {scanHistory.length} results
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Results List */}
      {filteredResults.length === 0 ? (
        <Alert severity="info">
          {scanHistory.length === 0 
            ? "No scan results yet. Run your first scan to see results here!"
            : "No results match your current filters."}
        </Alert>
      ) : (
        <List>
          {filteredResults.map((result, index) => {
            const actualIndex = scanHistory.indexOf(result);
            const vulnerabilityCount = result.vulnerabilities?.length || 0;
            const subdomainCount = result.subdomains?.length || 0;
            const target = result.domain || result.target || 'Unknown';
            
            return (
              <Card key={actualIndex} sx={{ mb: 2 }} className="fade-in">
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="h6" gutterBottom>
                        {target}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                        <Chip 
                          label={result.scan_type || 'Unknown'} 
                          color="primary" 
                          size="small" 
                        />
                        {vulnerabilityCount > 0 && (
                          <Chip 
                            label={`${vulnerabilityCount} issues`}
                            color={vulnerabilityCount > 5 ? 'error' : 'warning'}
                            size="small"
                            icon={<BugIcon />}
                          />
                        )}
                        {subdomainCount > 0 && (
                          <Chip 
                            label={`${subdomainCount} subdomains`}
                            color="info"
                            size="small"
                            icon={<SecurityIcon />}
                          />
                        )}
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Scanned: {new Date(result.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <IconButton 
                        color="primary" 
                        onClick={() => handleViewResult(result, actualIndex)}
                        title="View details"
                      >
                        <ViewIcon />
                      </IconButton>
                      <IconButton 
                        color="secondary" 
                        onClick={() => handleGenerateReport(result)}
                        title="Generate report"
                      >
                        <DownloadIcon />
                      </IconButton>
                      <IconButton 
                        color="error" 
                        onClick={() => handleDeleteResult(actualIndex)}
                        title="Delete result"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            );
          })}
        </List>
      )}

      {/* Result Detail Dialog */}
      <Dialog 
        open={dialogOpen} 
        onClose={() => setDialogOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: { minHeight: '80vh' }
        }}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">
              Scan Results: {selectedResult?.domain || selectedResult?.target || 'Unknown'}
            </Typography>
            <Chip 
              label={selectedResult?.scan_type || 'Unknown'} 
              color="primary" 
              size="small" 
            />
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {selectedResult && (
            <Box>
              {/* Scan Info */}
              <Typography variant="h6" gutterBottom>
                Scan Information
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>Target:</strong> {selectedResult.domain || selectedResult.target}<br/>
                <strong>Type:</strong> {selectedResult.scan_type}<br/>
                <strong>Date:</strong> {new Date(selectedResult.timestamp).toLocaleString()}
              </Typography>

              {/* Results based on scan type */}
              {selectedResult.vulnerabilities && renderVulnerabilities(selectedResult.vulnerabilities)}
              {selectedResult.subdomains && renderSubdomains(selectedResult.subdomains)}
              {selectedResult.scan_results && renderPortScan(selectedResult.scan_results)}
              
              {/* AI Analysis */}
              {selectedResult.ai_analysis && renderAIAnalysis(selectedResult.ai_analysis)}

              {/* Raw Data */}
              <Accordion sx={{ mt: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Raw Scan Data (JSON)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <ReactJson 
                    src={selectedResult} 
                    theme="monokai"
                    collapsed={2}
                    enableClipboard={true}
                    displayObjectSize={true}
                    displayDataTypes={false}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleGenerateReport(selectedResult)} color="secondary">
            Generate Report
          </Button>
          <Button onClick={() => setDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Results;
