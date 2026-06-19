import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Container,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Divider,
  useTheme,
  Alert,
  Snackbar
} from '@mui/material';
import {
  Menu as MenuIcon,
  Security as SecurityIcon,
  Dashboard as DashboardIcon,
  BugReport as BugReportIcon,
  Assessment as AssessmentIcon,
  SmartToy as AIIcon,
  Settings as SettingsIcon,
  Help as HelpIcon,
  AccountCircle as AccountIcon,
  Favorite as DonateIcon
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

// Import components
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import Results from './components/Results';
import Reports from './components/Reports';
import AIAssistant from './components/AIAssistant';
import Settings from './components/Settings';
import Help from './components/Help';
import Donate from './components/Donate';

// Import context
import { ScanProvider } from './context/ScanContext';

const drawerWidth = 240;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
  { text: 'Scanner', icon: <SecurityIcon />, path: '/scanner' },
  { text: 'Results', icon: <BugReportIcon />, path: '/results' },
  { text: 'Reports', icon: <AssessmentIcon />, path: '/reports' },
  { text: 'AI Assistant', icon: <AIIcon />, path: '/ai-assistant' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  { text: 'Help', icon: <HelpIcon />, path: '/help' },
  { text: 'About', icon: <DonateIcon />, path: '/about' },
];

function App() {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [alertMessage, setAlertMessage] = useState(null);

  const handleDrawerToggle = () => {
    setDrawerOpen(!drawerOpen);
  };

  const handleMenuClick = (path) => {
    navigate(path);
    setDrawerOpen(false);
  };

  const showAlert = (message, severity = 'info') => {
    setAlertMessage({ message, severity });
  };

  const hideAlert = () => {
    setAlertMessage(null);
  };

  useEffect(() => {
    // Redirect to dashboard if on root path
    if (location.pathname === '/') {
      navigate('/dashboard');
    }
  }, [location.pathname, navigate]);

  const drawer = (
    <Box>
      <Toolbar>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon sx={{ color: theme.palette.primary.main, fontSize: 32 }} />
          <Typography variant="h6" sx={{ fontWeight: 'bold', color: theme.palette.primary.main }}>
            Network Scanner
          </Typography>
        </Box>
      </Toolbar>
      <Divider />
      <List>
        {menuItems.map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton
              onClick={() => handleMenuClick(item.path)}
              selected={location.pathname === item.path}
              sx={{
                '&.Mui-selected': {
                  backgroundColor: theme.palette.primary.main + '20',
                  borderRight: `3px solid ${theme.palette.primary.main}`,
                },
              }}
            >
              <ListItemIcon sx={{ color: location.pathname === item.path ? theme.palette.primary.main : 'inherit' }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
      <Divider />
      <List>
        <ListItem disablePadding>
          <ListItemButton>
            <ListItemIcon>
              <AccountIcon />
            </ListItemIcon>
            <ListItemText primary="Profile" />
          </ListItemButton>
        </ListItem>
      </List>
    </Box>
  );

  return (
    <ScanProvider>
      <Box sx={{ display: 'flex' }}>
        {/* App Bar */}
        <AppBar
          position="fixed"
          sx={{
            width: { sm: `calc(100% - ${drawerWidth}px)` },
            ml: { sm: `${drawerWidth}px` },
            background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
            backdropFilter: 'blur(10px)',
          }}
        >
          <Toolbar>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              edge="start"
              onClick={handleDrawerToggle}
              sx={{ mr: 2, display: { sm: 'none' } }}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
              {menuItems.find(item => item.path === location.pathname)?.text || 'Network Scanner'}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                AI-Assisted Security Scanner
              </Typography>
            </Box>
          </Toolbar>
        </AppBar>

        {/* Navigation Drawer */}
        <Box
          component="nav"
          sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        >
          <Drawer
            variant="temporary"
            open={drawerOpen}
            onClose={handleDrawerToggle}
            ModalProps={{
              keepMounted: true,
            }}
            sx={{
              display: { xs: 'block', sm: 'none' },
              '& .MuiDrawer-paper': {
                boxSizing: 'border-box',
                width: drawerWidth,
                background: 'linear-gradient(180deg, #1a1a2e 0%, #16213e 100%)',
              },
            }}
          >
            {drawer}
          </Drawer>
          <Drawer
            variant="permanent"
            sx={{
              display: { xs: 'none', sm: 'block' },
              '& .MuiDrawer-paper': {
                boxSizing: 'border-box',
                width: drawerWidth,
                background: 'linear-gradient(180deg, #1a1a2e 0%, #16213e 100%)',
              },
            }}
            open
          >
            {drawer}
          </Drawer>
        </Box>

        {/* Main Content */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            p: 3,
            width: { sm: `calc(100% - ${drawerWidth}px)` },
            minHeight: '100vh',
          }}
        >
          <Toolbar />
          <Container maxWidth="xl" sx={{ mt: 2 }}>
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard showAlert={showAlert} />} />
              <Route path="/scanner" element={<Scanner showAlert={showAlert} />} />
              <Route path="/results" element={<Results showAlert={showAlert} />} />
              <Route path="/reports" element={<Reports showAlert={showAlert} />} />
              <Route path="/ai-assistant" element={<AIAssistant showAlert={showAlert} />} />
              <Route path="/settings" element={<Settings showAlert={showAlert} />} />
              <Route path="/help" element={<Help />} />
              <Route path="/about" element={<Donate />} />
            </Routes>
          </Container>
        </Box>

        {/* Notifications */}
        <Snackbar
          open={!!alertMessage}
          autoHideDuration={6000}
          onClose={hideAlert}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
          {alertMessage && (
            <Alert
              onClose={hideAlert}
              severity={alertMessage.severity}
              sx={{ width: '100%' }}
            >
              {alertMessage.message}
            </Alert>
          )}
        </Snackbar>
      </Box>
    </ScanProvider>
  );
}

export default App;
