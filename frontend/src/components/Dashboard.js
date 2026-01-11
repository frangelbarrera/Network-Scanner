import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Assessment as ReportIcon,
  TrendingUp as TrendingIcon,
  PlayArrow as PlayIcon,
  Visibility as ViewIcon,
  Add as AddIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useScan } from '../context/ScanContext';
import apiService from '../services/apiService';

const COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7c7c'];

const Dashboard = ({ showNotification }) => {
  const { scanHistory, startScan, scanProgress } = useScan();
  const [statistics, setStatistics] = useState(null);
  const [projects, setProjects] = useState([]);
  const [newProjectDialog, setNewProjectDialog] = useState(false);
  const [newProject, setNewProject] = useState({ name: '', description: '', target: '' });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [stats, projectsData] = await Promise.all([
        apiService.getStatistics(),
        apiService.getProjects()
      ]);
      setStatistics(stats);
      setProjects(projectsData);
    } catch (error) {
      showNotification('Failed to load dashboard data', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateProject = async () => {
    try {
      if (!newProject.name || !newProject.target) {
        showNotification('Please fill in required fields', 'error');
        return;
      }

      const project = await apiService.createProject(newProject);
      setProjects(prev => [project, ...prev]);
      setNewProjectDialog(false);
      setNewProject({ name: '', description: '', target: '' });
      showNotification('Project created successfully', 'success');
    } catch (error) {
      showNotification('Failed to create project', 'error');
    }
  };

  const handleQuickScan = async (target, scanType) => {
    try {
      await startScan(scanType, target);
      showNotification(`${scanType} scan started for ${target}`, 'info');
    } catch (error) {
      showNotification(`Failed to start scan: ${error.message}`, 'error');
    }
  };

  const vulnerabilityData = scanHistory.slice(0, 5).map((scan, index) => ({
    name: `Scan ${index + 1}`,
    vulnerabilities: scan.vulnerabilities?.length || 0,
    critical: scan.vulnerabilities?.filter(v => v.severity === 'Critical').length || 0,
    high: scan.vulnerabilities?.filter(v => v.severity === 'High').length || 0,
    medium: scan.vulnerabilities?.filter(v => v.severity === 'Medium').length || 0,
    low: scan.vulnerabilities?.filter(v => v.severity === 'Low').length || 0,
  }));

  const severityDistribution = [
    { name: 'Critical', value: scanHistory.reduce((acc, scan) => acc + (scan.vulnerabilities?.filter(v => v.severity === 'Critical').length || 0), 0) },
    { name: 'High', value: scanHistory.reduce((acc, scan) => acc + (scan.vulnerabilities?.filter(v => v.severity === 'High').length || 0), 0) },
    { name: 'Medium', value: scanHistory.reduce((acc, scan) => acc + (scan.vulnerabilities?.filter(v => v.severity === 'Medium').length || 0), 0) },
    { name: 'Low', value: scanHistory.reduce((acc, scan) => acc + (scan.vulnerabilities?.filter(v => v.severity === 'Low').length || 0), 0) },
  ].filter(item => item.value > 0);

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setNewProjectDialog(true)}
          >
            New Project
          </Button>
          <IconButton onClick={loadDashboardData} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card">
            <CardContent sx={{ textAlign: 'center' }}>
              <SecurityIcon sx={{ fontSize: 40, color: '#3f51b5', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number">
                {statistics?.total_scans || scanHistory.length}
              </Typography>
              <Typography className="stat-label">Total Scans</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card">
            <CardContent sx={{ textAlign: 'center' }}>
              <BugIcon sx={{ fontSize: 40, color: '#f44336', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number">
                {statistics?.vulnerabilities_found || scanHistory.reduce((acc, scan) => acc + (scan.vulnerabilities?.length || 0), 0)}
              </Typography>
              <Typography className="stat-label">Vulnerabilities Found</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card">
            <CardContent sx={{ textAlign: 'center' }}>
              <ReportIcon sx={{ fontSize: 40, color: '#ff9800', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number">
                {projects.length}
              </Typography>
              <Typography className="stat-label">Active Projects</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card">
            <CardContent sx={{ textAlign: 'center' }}>
              <TrendingIcon sx={{ fontSize: 40, color: '#4caf50', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number">
                {statistics?.success_rate || '95.2'}%
              </Typography>
              <Typography className="stat-label">Success Rate</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Current Scan Progress */}
      {scanProgress && (
        <Card sx={{ mb: 3 }} className="fade-in">
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan in Progress
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {scanProgress.message}
            </Typography>
            <LinearProgress className="pulsing" />
          </CardContent>
        </Card>
      )}

      <Grid container spacing={3}>
        {/* Recent Scans */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Scans
              </Typography>
              {scanHistory.length === 0 ? (
                <Alert severity="info">
                  No scans yet. Start your first scan to see results here!
                </Alert>
              ) : (
                <List>
                  {scanHistory.slice(0, 5).map((scan, index) => (
                    <ListItem key={index} divider>
                      <ListItemIcon>
                        <SecurityIcon />
                      </ListItemIcon>
                      <ListItemText
                        primary={`${scan.domain || scan.target || 'Unknown Target'}`}
                        secondary={`${scan.scan_type || 'Unknown'} scan - ${new Date(scan.timestamp).toLocaleString()}`}
                      />
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        {scan.vulnerabilities && (
                          <Chip
                            label={`${scan.vulnerabilities.length} issues`}
                            size="small"
                            color={scan.vulnerabilities.length > 5 ? 'error' : 'default'}
                          />
                        )}
                        <IconButton size="small">
                          <ViewIcon />
                        </IconButton>
                      </Box>
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Projects */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Projects
              </Typography>
              {projects.length === 0 ? (
                <Alert severity="info">
                  No projects yet. Create your first project to organize your scans!
                </Alert>
              ) : (
                <List>
                  {projects.slice(0, 5).map((project) => (
                    <ListItem key={project.id} divider>
                      <ListItemText
                        primary={project.name}
                        secondary={`Target: ${project.target} • ${project.scan_count} scans`}
                      />
                      <Chip
                        label={project.status}
                        size="small"
                        color={project.status === 'active' ? 'success' : 'default'}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Vulnerability Trends */}
        {vulnerabilityData.length > 0 && (
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Trends
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={vulnerabilityData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="critical" fill="#9c27b0" />
                    <Bar dataKey="high" fill="#f44336" />
                    <Bar dataKey="medium" fill="#ff9800" />
                    <Bar dataKey="low" fill="#4caf50" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Severity Distribution */}
        {severityDistribution.length > 0 && (
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Severity Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityDistribution}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Quick Actions */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quick Actions
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target domain:');
                      if (target) handleQuickScan(target, 'subdomain');
                    }}
                  >
                    Subdomain Scan
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target IP/domain:');
                      if (target) handleQuickScan(target, 'port');
                    }}
                  >
                    Port Scan
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target URL:');
                      if (target) handleQuickScan(target, 'vulnerability');
                    }}
                  >
                    Vuln Scan
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target domain:');
                      if (target) handleQuickScan(target, 'automated');
                    }}
                  >
                    Full Scan
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Support SecScanX Section */}
      <Card sx={{ mt: 4, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
        <CardContent sx={{ textAlign: 'center' }}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            ❤️ Support SecScanX Development
          </Typography>
          <Typography variant="body1" paragraph>
            Help us build better security tools! Your support enables new features, AI improvements, and educational resources.
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              color="warning"
              size="large"
              onClick={() => window.location.href = '/donate'}
              sx={{ 
                backgroundColor: 'rgba(255, 255, 255, 0.2)', 
                '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.3)' } 
              }}
            >
              💰 Donate Now
            </Button>
            <Button
              variant="outlined"
              color="inherit"
              size="large"
              onClick={() => window.open('https://github.com/yashab-cyber/SecScanX', '_blank')}
              sx={{ 
                borderColor: 'rgba(255, 255, 255, 0.5)',
                '&:hover': { borderColor: 'white', backgroundColor: 'rgba(255, 255, 255, 0.1)' }
              }}
            >
              ⭐ Star on GitHub
            </Button>
          </Box>
          <Typography variant="body2" sx={{ mt: 2, opacity: 0.9 }}>
            Made with ❤️ by Yashab Alam (ZehraSec) • Crypto donations accepted
          </Typography>
        </CardContent>
      </Card>

      {/* New Project Dialog */}
      <Dialog open={newProjectDialog} onClose={() => setNewProjectDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Project</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Project Name *"
            fullWidth
            variant="outlined"
            value={newProject.name}
            onChange={(e) => setNewProject(prev => ({ ...prev, name: e.target.value }))}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Description"
            fullWidth
            multiline
            rows={3}
            variant="outlined"
            value={newProject.description}
            onChange={(e) => setNewProject(prev => ({ ...prev, description: e.target.value }))}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Target Domain/IP *"
            fullWidth
            variant="outlined"
            value={newProject.target}
            onChange={(e) => setNewProject(prev => ({ ...prev, target: e.target.value }))}
            helperText="e.g., example.com or 192.168.1.1"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewProjectDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateProject} variant="contained">Create</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard;
