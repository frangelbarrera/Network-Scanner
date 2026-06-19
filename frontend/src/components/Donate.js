import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Paper,
  Link
} from '@mui/material';
import {
  Security as SecurityIcon,
  Code as CodeIcon,
  GitHub as GitHubIcon,
  Star as StarIcon
} from '@mui/icons-material';

const Donate = () => {
  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ textAlign: 'center', mb: 4 }}>
        <Typography variant="h3" component="h1" gutterBottom sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
          <SecurityIcon color="primary" fontSize="large" />
          About Network Scanner
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 800, mx: 'auto' }}>
          Open-source network reconnaissance and vulnerability assessment tool
        </Typography>
      </Box>

      {/* About */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <StarIcon color="primary" />
            About This Project
          </Typography>
          <Typography variant="body1" paragraph>
            Network Scanner is an open-source project for network reconnaissance, 
            vulnerability scanning, and security assessment. It combines traditional 
            scanning techniques with AI-assisted analysis to help security professionals 
            and enthusiasts identify and understand network vulnerabilities.
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', height: '100%' }}>
                <Box sx={{ color: 'primary.main', mb: 1 }}>
                  <SecurityIcon />
                </Box>
                <Typography variant="h6" gutterBottom>
                  Security Research
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Vulnerability detection and network analysis
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', height: '100%' }}>
                <Box sx={{ color: 'primary.main', mb: 1 }}>
                  <CodeIcon />
                </Box>
                <Typography variant="h6" gutterBottom>
                  Development
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  New features, bug fixes, and AI improvements
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', height: '100%' }}>
                <Box sx={{ color: 'primary.main', mb: 1 }}>
                  <GitHubIcon />
                </Box>
                <Typography variant="h6" gutterBottom>
                  Open Source
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Free and open for the community
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', height: '100%' }}>
                <Box sx={{ color: 'primary.main', mb: 1 }}>
                  <StarIcon />
                </Box>
                <Typography variant="h6" gutterBottom>
                  Community
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Supporting contributors and open-source initiatives
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* GitHub Links */}
      <Card>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Project Links
          </Typography>
          <Typography variant="body1" paragraph>
            Network Scanner is maintained and developed on GitHub. Contributions, issues, 
            and feedback are welcome.
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Repository
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Button
                  variant="outlined"
                  startIcon={<GitHubIcon />}
                  href="https://github.com/frangelbarrera/Network-Scanner"
                  target="_blank"
                >
                  GitHub Repository
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<StarIcon />}
                  href="https://github.com/frangelbarrera/Network-Scanner"
                  target="_blank"
                >
                  Star on GitHub
                </Button>
              </Box>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Developer
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Button
                  variant="outlined"
                  startIcon={<GitHubIcon />}
                  href="https://github.com/frangelbarrera"
                  target="_blank"
                >
                  @frangelbarrera
                </Button>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Footer */}
      <Box sx={{ textAlign: 'center', mt: 4, p: 3, backgroundColor: 'primary.main', color: 'white', borderRadius: 2 }}>
        <SecurityIcon sx={{ fontSize: 40, mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          Network Scanner
        </Typography>
        <Typography variant="body1">
          Open-source security tool for the community. Built with ❤️ by frangelbarrera.
        </Typography>
      </Box>
    </Box>
  );
};

export default Donate;
