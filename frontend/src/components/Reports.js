import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Grid,
  Alert,
  CircularProgress,
  Tooltip
} from '@mui/material';
import {
  Download as DownloadIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Share as ShareIcon,
  FilterList as FilterIcon,
  FileDownload as ExportIcon,
  Assessment as ReportIcon,
  Print as PrintIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const Reports = ({ showNotification }) => {
  const { reports, generateReport, deleteReport, exportReport } = useScan();
  const [filteredReports, setFilteredReports] = useState([]);
  const [filterType, setFilterType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [reportToDelete, setReportToDelete] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    filterReports();
  }, [reports, filterType, searchTerm]);

  const filterReports = () => {
    let filtered = reports || [];

    // Filter by type
    if (filterType !== 'all') {
      filtered = filtered.filter(report => report.type === filterType);
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(report => 
        report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        report.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
        report.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredReports(filtered);
  };

  const handleViewReport = (report) => {
    setSelectedReport(report);
    setViewDialogOpen(true);
  };

  const handleDeleteClick = (report) => {
    setReportToDelete(report);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!reportToDelete) return;

    setIsLoading(true);
    try {
      await deleteReport(reportToDelete.id);
      showNotification('Report deleted successfully', 'success');
      setDeleteDialogOpen(false);
      setReportToDelete(null);
    } catch (error) {
      showNotification('Failed to delete report', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownload = async (report, format) => {
    setIsLoading(true);
    try {
      const blob = await exportReport(report.id, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `${report.title.replace(/\s+/g, '_')}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      showNotification(`Report downloaded as ${format.toUpperCase()}`, 'success');
    } catch (error) {
      showNotification('Failed to download report', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getReportTypeIcon = (type) => {
    switch (type) {
      case 'vulnerability_assessment': return '🔍';
      case 'penetration_test': return '🎯';
      case 'reconnaissance': return '🕵️';
      case 'compliance': return '📋';
      default: return '📄';
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          📊 Security Reports
        </Typography>
        <Button
          variant="contained"
          startIcon={<ReportIcon />}
          onClick={() => {/* Navigate to scanner or trigger new report generation */}}
        >
          Generate New Report
        </Button>
      </Box>

      {/* Filter and Search Controls */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Search Reports"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                variant="outlined"
                size="small"
              />
            </Grid>
            <Grid item xs={12} sm={3}>
              <TextField
                fullWidth
                select
                label="Filter by Type"
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                variant="outlined"
                size="small"
              >
                <MenuItem value="all">All Types</MenuItem>
                <MenuItem value="vulnerability_assessment">Vulnerability Assessment</MenuItem>
                <MenuItem value="penetration_test">Penetration Test</MenuItem>
                <MenuItem value="reconnaissance">Reconnaissance</MenuItem>
                <MenuItem value="compliance">Compliance</MenuItem>
              </TextField>
            </Grid>
            <Grid item xs={12} sm={5}>
              <Typography variant="body2" color="text.secondary">
                {filteredReports.length} of {reports?.length || 0} reports shown
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Reports Table */}
      {filteredReports.length === 0 ? (
        <Card>
          <CardContent>
            <Alert severity="info">
              No reports found. Generate your first security report by running a scan.
            </Alert>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Report</TableCell>
                  <TableCell>Target</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Findings</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredReports.map((report) => (
                  <TableRow key={report.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <span>{getReportTypeIcon(report.type)}</span>
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                            {report.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {report.description}
                          </Typography>
                        </Box>
                      </Box>
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {report.target}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Chip 
                        label={report.type.replace('_', ' ')}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    
                    <TableCell>
                      <Chip 
                        label={`${report.findings_count || 0} findings`}
                        size="small"
                        color={report.findings_count > 0 ? 'primary' : 'default'}
                      />
                    </TableCell>
                    
                    <TableCell>
                      {report.max_severity && (
                        <Chip 
                          label={report.max_severity}
                          size="small"
                          color={getSeverityColor(report.max_severity)}
                        />
                      )}
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2">
                        {formatDate(report.created_at)}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="View Report">
                          <IconButton 
                            size="small" 
                            onClick={() => handleViewReport(report)}
                          >
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
                        
                        <Tooltip title="Download PDF">
                          <IconButton 
                            size="small"
                            onClick={() => handleDownload(report, 'pdf')}
                          >
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                        
                        <Tooltip title="Export HTML">
                          <IconButton 
                            size="small"
                            onClick={() => handleDownload(report, 'html')}
                          >
                            <ExportIcon />
                          </IconButton>
                        </Tooltip>
                        
                        <Tooltip title="Delete Report">
                          <IconButton 
                            size="small"
                            color="error"
                            onClick={() => handleDeleteClick(report)}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}

      {/* View Report Dialog */}
      <Dialog 
        open={viewDialogOpen} 
        onClose={() => setViewDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            {selectedReport?.title}
            <Box>
              <IconButton onClick={() => handleDownload(selectedReport, 'pdf')}>
                <PrintIcon />
              </IconButton>
              <IconButton onClick={() => handleDownload(selectedReport, 'html')}>
                <ShareIcon />
              </IconButton>
            </Box>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedReport && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">Target</Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                    {selectedReport.target}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">Type</Typography>
                  <Typography variant="body1">
                    {selectedReport.type.replace('_', ' ')}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">Created</Typography>
                  <Typography variant="body1">
                    {formatDate(selectedReport.created_at)}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">Findings</Typography>
                  <Typography variant="body1">
                    {selectedReport.findings_count || 0} security issues found
                  </Typography>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom>Executive Summary</Typography>
              <Typography variant="body1" paragraph>
                {selectedReport.summary || selectedReport.description}
              </Typography>

              {selectedReport.findings && selectedReport.findings.length > 0 && (
                <>
                  <Typography variant="h6" gutterBottom>Key Findings</Typography>
                  <Box sx={{ mb: 2 }}>
                    {selectedReport.findings.slice(0, 5).map((finding, index) => (
                      <Alert 
                        key={index} 
                        severity={getSeverityColor(finding.severity).replace('error', 'error').replace('warning', 'warning').replace('info', 'info').replace('success', 'success')}
                        sx={{ mb: 1 }}
                      >
                        <Typography variant="subtitle2">{finding.title}</Typography>
                        <Typography variant="body2">{finding.description}</Typography>
                      </Alert>
                    ))}
                    {selectedReport.findings.length > 5 && (
                      <Typography variant="body2" color="text.secondary">
                        ...and {selectedReport.findings.length - 5} more findings in the full report
                      </Typography>
                    )}
                  </Box>
                </>
              )}

              {selectedReport.recommendations && (
                <>
                  <Typography variant="h6" gutterBottom>Recommendations</Typography>
                  <Typography variant="body1">
                    {selectedReport.recommendations}
                  </Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>Close</Button>
          <Button 
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={() => handleDownload(selectedReport, 'pdf')}
          >
            Download PDF
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog 
        open={deleteDialogOpen} 
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Delete Report</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete "{reportToDelete?.title}"? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button 
            color="error" 
            variant="contained"
            onClick={handleDeleteConfirm}
            disabled={isLoading}
            startIcon={isLoading ? <CircularProgress size={16} /> : <DeleteIcon />}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Reports;
