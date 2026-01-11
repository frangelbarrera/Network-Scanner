import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Alert,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Link
} from '@mui/material';
import {
  Favorite as FavoriteIcon,
  AttachMoney as MoneyIcon,
  Security as SecurityIcon,
  School as SchoolIcon,
  Code as CodeIcon,
  Group as GroupIcon,
  ContentCopy as CopyIcon,
  Launch as LaunchIcon,
  Bitcoin as BitcoinIcon,
  AccountBalance as BankIcon,
  CreditCard as PayPalIcon,
  Star as StarIcon,
  EmojiEvents as TrophyIcon,
  Support as SupportIcon
} from '@mui/icons-material';

const Donate = () => {
  const [copySuccess, setCopySuccess] = useState('');
  const [selectedWallet, setSelectedWallet] = useState(null);

  const copyToClipboard = async (text, type) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopySuccess(`${type} address copied!`);
      setTimeout(() => setCopySuccess(''), 3000);
    } catch (err) {
      setCopySuccess('Failed to copy');
    }
  };

  const donationGoals = [
    {
      title: "Advanced Vulnerability Scanner",
      target: 3000,
      current: 0,
      description: "AI-powered vulnerability detection and automated exploit development"
    },
    {
      title: "Mobile Penetration Testing Suite",
      target: 5000,
      current: 0,
      description: "Android/iOS security assessment tools and wireless testing"
    },
    {
      title: "Enterprise Security Platform",
      target: 10000,
      current: 0,
      description: "Multi-target scanning, team collaboration, and enterprise features"
    }
  ];

  const donationTiers = [
    {
      name: "Bronze Supporter",
      amount: "$5-$24",
      icon: <SecurityIcon color="primary" />,
      benefits: [
        "Name in CONTRIBUTORS.md",
        "Special supporter badge",
        "Early access to beta releases",
        "Monthly project updates"
      ]
    },
    {
      name: "Silver Supporter",
      amount: "$25-$99",
      icon: <StarIcon sx={{ color: '#C0C0C0' }} />,
      benefits: [
        "All Bronze benefits",
        "Priority support",
        "Custom vulnerability signatures",
        "Direct development team access",
        "Quarterly technical briefings"
      ]
    },
    {
      name: "Gold Sponsor",
      amount: "$100-$499",
      icon: <StarIcon sx={{ color: '#FFD700' }} />,
      benefits: [
        "All Silver benefits",
        "Feature request priority",
        "Custom dashboard branding",
        "Dedicated support channel",
        "Monthly 1-on-1 consultations"
      ]
    },
    {
      name: "Platinum Partner",
      amount: "$500+",
      icon: <TrophyIcon sx={{ color: '#E5E4E2' }} />,
      benefits: [
        "All Gold benefits",
        "Custom development requests",
        "Enterprise support package",
        "Joint research opportunities",
        "Partnership announcements"
      ]
    }
  ];

  const cryptoWallets = [
    {
      name: "Solana (SOL)",
      address: "5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT",
      status: "ACTIVE",
      recommended: true
    },
    {
      name: "Bitcoin (BTC)",
      address: "bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c",
      status: "ACTIVE"
    },
    {
      name: "Ethereum (ETH)",
      address: "Contact yashabalam707@gmail.com",
      status: "CONTACT"
    }
  ];

  const impactAreas = [
    { icon: <SecurityIcon />, title: "Security Research", description: "Vulnerability detection and exploit development" },
    { icon: <CodeIcon />, title: "Development", description: "New features, bug fixes, and AI improvements" },
    { icon: <SchoolIcon />, title: "Education", description: "Tutorials, documentation, and training materials" },
    { icon: <GroupIcon />, title: "Community", description: "Supporting contributors and open-source initiatives" }
  ];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ textAlign: 'center', mb: 4 }}>
        <Typography variant="h3" component="h1" gutterBottom sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
          <FavoriteIcon color="error" fontSize="large" />
          Support SecScanX Development
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 800, mx: 'auto' }}>
          Help us build the future of AI-assisted vulnerability assessment and penetration testing tools
        </Typography>
      </Box>

      {copySuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {copySuccess}
        </Alert>
      )}

      {/* Why Support Matters */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SupportIcon color="primary" />
            Why Your Support Matters
          </Typography>
          <Typography variant="body1" paragraph>
            SecScanX is an open-source project created by <strong>Yashab Alam</strong>, founder and CEO of ZehraSec. 
            Your donations directly impact security professionals, students, and organizations worldwide.
          </Typography>
          <Grid container spacing={2}>
            {impactAreas.map((area, index) => (
              <Grid item xs={12} sm={6} md={3} key={index}>
                <Paper sx={{ p: 2, textAlign: 'center', height: '100%' }}>
                  <Box sx={{ color: 'primary.main', mb: 1 }}>
                    {area.icon}
                  </Box>
                  <Typography variant="h6" gutterBottom>
                    {area.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {area.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Donation Methods */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Cryptocurrency */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BitcoinIcon color="warning" />
                Cryptocurrency (Recommended)
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Secure, fast, and anonymous donations
              </Typography>
              
              {cryptoWallets.map((wallet, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2, position: 'relative' }}>
                  <Box sx={{ display: 'flex', justifiContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="h6">
                      {wallet.name}
                      {wallet.recommended && (
                        <Chip 
                          label="Recommended" 
                          size="small" 
                          color="primary" 
                          sx={{ ml: 1 }} 
                        />
                      )}
                    </Typography>
                    <Chip 
                      label={wallet.status} 
                      size="small" 
                      color={wallet.status === 'ACTIVE' ? 'success' : 'warning'} 
                    />
                  </Box>
                  <Typography 
                    variant="body2" 
                    sx={{ 
                      fontFamily: 'monospace', 
                      wordBreak: 'break-all',
                      backgroundColor: 'grey.100',
                      p: 1,
                      borderRadius: 1,
                      mb: 1
                    }}
                  >
                    {wallet.address}
                  </Typography>
                  {wallet.status === 'ACTIVE' && (
                    <Button
                      size="small"
                      startIcon={<CopyIcon />}
                      onClick={() => copyToClipboard(wallet.address, wallet.name)}
                    >
                      Copy Address
                    </Button>
                  )}
                </Paper>
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Traditional Methods */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PayPalIcon color="primary" />
                Traditional Payment Methods
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Familiar and widely accepted options
              </Typography>

              <Paper sx={{ p: 3, mb: 3, textAlign: 'center' }}>
                <PayPalIcon sx={{ fontSize: 40, color: '#0070ba', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  PayPal
                </Typography>
                <Typography variant="body2" gutterBottom>
                  Email: yashabalam707@gmail.com
                </Typography>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<LaunchIcon />}
                  href="https://paypal.me/yashab07"
                  target="_blank"
                  sx={{ mt: 1 }}
                >
                  Donate via PayPal
                </Button>
              </Paper>

              <Alert severity="info">
                <Typography variant="body2">
                  For large donations ($1000+) or enterprise partnerships, 
                  please contact us at <strong>yashabalam707@gmail.com</strong> for 
                  wire transfer options.
                </Typography>
              </Alert>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Donation Tiers */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrophyIcon color="warning" />
            Supporter Tiers & Benefits
          </Typography>
          <Grid container spacing={2}>
            {donationTiers.map((tier, index) => (
              <Grid item xs={12} sm={6} md={3} key={index}>
                <Paper sx={{ p: 2, height: '100%', textAlign: 'center' }}>
                  <Box sx={{ mb: 2 }}>
                    {tier.icon}
                  </Box>
                  <Typography variant="h6" gutterBottom>
                    {tier.name}
                  </Typography>
                  <Typography variant="h5" color="primary" gutterBottom>
                    {tier.amount}
                  </Typography>
                  <List dense>
                    {tier.benefits.map((benefit, benefitIndex) => (
                      <ListItem key={benefitIndex} sx={{ py: 0.5 }}>
                        <ListItemText 
                          primary={benefit} 
                          primaryTypographyProps={{ variant: 'body2' }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Funding Goals */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Current Funding Goals
          </Typography>
          {donationGoals.map((goal, index) => (
            <Paper key={index} sx={{ p: 3, mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="h6">
                  {goal.title}
                </Typography>
                <Typography variant="h6" color="primary">
                  ${goal.current.toLocaleString()} / ${goal.target.toLocaleString()}
                </Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={(goal.current / goal.target) * 100} 
                sx={{ mb: 2, height: 8, borderRadius: 4 }}
              />
              <Typography variant="body2" color="text.secondary">
                {goal.description}
              </Typography>
            </Paper>
          ))}
        </CardContent>
      </Card>

      {/* ZehraSec Links */}
      <Card>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Connect with ZehraSec
          </Typography>
          <Typography variant="body1" paragraph>
            SecScanX is developed by <strong>Yashab Alam</strong>, founder and CEO of ZehraSec, 
            a cybersecurity company focused on innovative security solutions.
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Official Channels
              </Typography>
              <List>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://www.zehrasec.com" target="_blank" rel="noopener">
                        🌐 www.zehrasec.com
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://www.instagram.com/_zehrasec?igsh=bXM0cWl1ejdoNHM4" target="_blank" rel="noopener">
                        📸 @_zehrasec (Instagram)
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://x.com/zehrasec?t=Tp9LOesZw2d2yTZLVo0_GA&s=08" target="_blank" rel="noopener">
                        🐦 @zehrasec (X/Twitter)
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://www.linkedin.com/company/zehrasec" target="_blank" rel="noopener">
                        💼 ZehraSec Company (LinkedIn)
                      </Link>
                    }
                  />
                </ListItem>
              </List>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Connect with Yashab Alam
              </Typography>
              <List>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://github.com/yashab-cyber" target="_blank" rel="noopener">
                        💻 @yashab-cyber (GitHub)
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://www.instagram.com/yashab.alam" target="_blank" rel="noopener">
                        📸 @yashab.alam (Instagram)
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary={
                      <Link href="https://www.linkedin.com/in/yashab-alam" target="_blank" rel="noopener">
                        💼 Yashab Alam (LinkedIn)
                      </Link>
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="📧 yashabalam707@gmail.com"
                  />
                </ListItem>
              </List>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Thank You Message */}
      <Box sx={{ textAlign: 'center', mt: 4, p: 3, backgroundColor: 'primary.main', color: 'white', borderRadius: 2 }}>
        <FavoriteIcon sx={{ fontSize: 40, mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          Thank You for Supporting SecScanX!
        </Typography>
        <Typography variant="body1">
          Every contribution helps make SecScanX better for security professionals, 
          students, and organizations worldwide. Together, we're building the future of 
          AI-assisted penetration testing!
        </Typography>
      </Box>
    </Box>
  );
};

export default Donate;
