import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Button,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Paper
} from '@mui/material';
import {
  School as SchoolIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  NetworkCheck as NetworkIcon,
  Assessment as AssessmentIcon,
  Report as ReportIcon,
  Api as ApiIcon,
  Terminal as TerminalIcon,
  Help as HelpIcon,
  ExpandMore as ExpandMoreIcon,
  Launch as LaunchIcon,
  YouTube as YouTubeIcon,
  MenuBook as BookIcon,
  Code as CodeIcon
} from '@mui/icons-material';

const Help = () => {
  const quickStartSteps = [
    {
      title: "1. Configure AI Assistant",
      description: "Add your OpenAI API key in Settings to enable intelligent analysis",
      icon: <ApiIcon color="primary" />
    },
    {
      title: "2. Start with Basic Reconnaissance",
      description: "Use subdomain enumeration or port scanning on a target domain",
      icon: <NetworkIcon color="primary" />
    },
    {
      title: "3. Review Results",
      description: "Analyze findings and get AI-powered recommendations",
      icon: <AssessmentIcon color="primary" />
    },
    {
      title: "4. Generate Reports",
      description: "Create professional PDF or HTML reports for documentation",
      icon: <ReportIcon color="primary" />
    }
  ];

  const scanTypes = [
    {
      name: "Subdomain Enumeration",
      description: "Discover subdomains using brute force, certificate transparency, and DNS techniques",
      usage: "secscanx scan subdomain example.com",
      webUsage: "Scanner → Reconnaissance → Subdomain Enumeration"
    },
    {
      name: "Port Scanning",
      description: "Identify open ports and running services on target systems",
      usage: "secscanx scan ports example.com",
      webUsage: "Scanner → Reconnaissance → Port Scan"
    },
    {
      name: "DNS Enumeration",
      description: "Gather DNS records and configuration information",
      usage: "secscanx scan dns example.com",
      webUsage: "Scanner → Reconnaissance → DNS Enumeration"
    },
    {
      name: "Web Vulnerability Scan",
      description: "Test web applications for common security vulnerabilities",
      usage: "secscanx scan web https://example.com",
      webUsage: "Scanner → Web Application → Vulnerability Scan"
    },
    {
      name: "Full Assessment",
      description: "Comprehensive security assessment combining multiple scan types",
      usage: "secscanx scan full example.com",
      webUsage: "Scanner → Full Assessment"
    }
  ];

  const troubleshooting = [
    {
      problem: "AI Assistant not working",
      solution: "Check your OpenAI API key in Settings. Ensure you have sufficient API credits.",
      severity: "high"
    },
    {
      problem: "Scans timing out",
      solution: "Increase timeout values in Settings or check your network connection.",
      severity: "medium"
    },
    {
      problem: "No results for subdomain enumeration",
      solution: "Try different wordlists or enable certificate transparency lookup.",
      severity: "low"
    },
    {
      problem: "Port scan blocked",
      solution: "Some networks block port scanning. Use VPN or reduce scan intensity.",
      severity: "medium"
    },
    {
      problem: "Report generation fails",
      solution: "Check available disk space and ensure proper permissions.",
      severity: "low"
    }
  ];

  const resources = [
    {
      title: "OWASP Top 10",
      description: "Most critical web application security risks",
      url: "https://owasp.org/www-project-top-ten/",
      type: "guide"
    },
    {
      title: "Penetration Testing Execution Standard",
      description: "Comprehensive guide to penetration testing methodology",
      url: "http://www.pentest-standard.org/",
      type: "guide"
    },
    {
      title: "Nmap Network Scanning",
      description: "Official Nmap documentation and tutorials",
      url: "https://nmap.org/book/",
      type: "documentation"
    },
    {
      title: "Web Application Security Testing",
      description: "OWASP Testing Guide for web applications",
      url: "https://owasp.org/www-project-web-security-testing-guide/",
      type: "guide"
    }
  ];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mb: 3 }}>
        📚 Help & Documentation
      </Typography>

      <Grid container spacing={3}>
        {/* Quick Start Guide */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <SchoolIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Quick Start Guide
              </Typography>
              <List>
                {quickStartSteps.map((step, index) => (
                  <ListItem key={index} alignItems="flex-start">
                    <ListItemIcon>
                      {step.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={step.title}
                      secondary={step.description}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Types Reference */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Scan Types
              </Typography>
              <List dense>
                {scanTypes.map((scan, index) => (
                  <React.Fragment key={index}>
                    <ListItem>
                      <ListItemText
                        primary={scan.name}
                        secondary={
                          <>
                            <Typography variant="body2" paragraph>
                              {scan.description}
                            </Typography>
                            <Typography variant="caption" display="block" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', p: 0.5, borderRadius: 1 }}>
                              CLI: {scan.usage}
                            </Typography>
                            <Typography variant="caption" display="block" color="primary">
                              Web: {scan.webUsage}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                    {index < scanTypes.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* CLI Reference */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TerminalIcon />
                <Typography variant="h6">Command Line Interface</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    Basic Commands
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.900', color: 'grey.100', fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    <div># Install SecScanX</div>
                    <div>pip install -e .</div>
                    <br />
                    <div># Show help</div>
                    <div>secscanx --help</div>
                    <br />
                    <div># Basic scan</div>
                    <div>secscanx scan subdomain example.com</div>
                    <br />
                    <div># Scan with output file</div>
                    <div>secscanx scan ports example.com -o results.json</div>
                    <br />
                    <div># Generate report</div>
                    <div>secscanx report results.json --format pdf</div>
                  </Paper>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    Advanced Options
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.900', color: 'grey.100', fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    <div># Enable learning mode</div>
                    <div>secscanx --learning scan web https://example.com</div>
                    <br />
                    <div># Custom timeout and threads</div>
                    <div>secscanx scan ports example.com --timeout 60 --threads 20</div>
                    <br />
                    <div># Verbose output</div>
                    <div>secscanx -v scan full example.com</div>
                    <br />
                    <div># Save to specific project</div>
                    <div>secscanx scan subdomain example.com --project "client-audit"</div>
                  </Paper>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Troubleshooting */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BugIcon />
                <Typography variant="h6">Troubleshooting</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {troubleshooting.map((item, index) => (
                  <React.Fragment key={index}>
                    <ListItem alignItems="flex-start">
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {item.problem}
                            <Chip 
                              label={item.severity}
                              size="small"
                              color={getSeverityColor(item.severity)}
                            />
                          </Box>
                        }
                        secondary={item.solution}
                      />
                    </ListItem>
                    {index < troubleshooting.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Learning Resources */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <BookIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Learning Resources
              </Typography>
              <Grid container spacing={2}>
                {resources.map((resource, index) => (
                  <Grid item xs={12} sm={6} key={index}>
                    <Paper sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
                      <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                        {resource.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
                        {resource.description}
                      </Typography>
                      <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Chip 
                          label={resource.type}
                          size="small"
                          variant="outlined"
                        />
                        <Button
                          size="small"
                          endIcon={<LaunchIcon />}
                          href={resource.url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Open
                        </Button>
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* API Documentation */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CodeIcon />
                <Typography variant="h6">API Documentation</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    REST API Endpoints
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                    <Typography variant="body2" component="div" sx={{ fontFamily: 'monospace' }}>
                      <div><strong>GET</strong> /api/health - Health check</div>
                      <div><strong>POST</strong> /api/scan/subdomain - Subdomain enumeration</div>
                      <div><strong>POST</strong> /api/scan/ports - Port scanning</div>
                      <div><strong>POST</strong> /api/scan/dns - DNS enumeration</div>
                      <div><strong>POST</strong> /api/scan/web - Web vulnerability scan</div>
                      <div><strong>GET</strong> /api/results/{`{id}`} - Get scan results</div>
                      <div><strong>POST</strong> /api/report/generate - Generate report</div>
                      <div><strong>POST</strong> /api/ai/chat - AI assistant chat</div>
                    </Typography>
                  </Paper>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    Example API Usage
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.900', color: 'grey.100', fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    <div># Start a subdomain scan</div>
                    <div>curl -X POST http://localhost:5000/api/scan/subdomain \</div>
                    <div>  -H "Content-Type: application/json" \</div>
                    <div>  -d '{`{"domain": "example.com"}`}'</div>
                    <br />
                    <div># Get scan results</div>
                    <div>curl http://localhost:5000/api/results/123</div>
                    <br />
                    <div># Chat with AI</div>
                    <div>curl -X POST http://localhost:5000/api/ai/chat \</div>
                    <div>  -H "Content-Type: application/json" \</div>
                    <div>  -d '{`{"message": "Explain this vulnerability"}`}'</div>
                  </Paper>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Support */}
        <Grid item xs={12}>
          <Alert severity="info">
            <Typography variant="h6" gutterBottom>
              Need More Help?
            </Typography>
            <Typography variant="body2" paragraph>
              SecScanX is an open-source project. If you encounter issues or need additional help:
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<CodeIcon />}
                href="https://github.com/secscanx/secscanx"
                target="_blank"
              >
                GitHub Repository
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<BugIcon />}
                href="https://github.com/secscanx/secscanx/issues"
                target="_blank"
              >
                Report Issues
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<HelpIcon />}
                href="https://github.com/secscanx/secscanx/discussions"
                target="_blank"
              >
                Community Support
              </Button>
            </Box>
          </Alert>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Help;
