// src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import VulnerabilityDashboard from './components/VulnerabilityDashboard';
import VulnerabilityDetailsPage from './components/VulnerabilityDetailsPage';

const futuristicTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#00e5ff' },
    secondary: { main: '#ff4081' },
    background: { default: '#000000', paper: '#1c1c1c' },
  },
  typography: { fontFamily: '"Orbitron", sans-serif' },
  components: {
    MuiButton: {
      styleOverrides: { root: { textTransform: 'none', borderRadius: 8 } },
    },
    MuiPaper: {
      styleOverrides: { root: { background: '#1c1c1c' } },
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={futuristicTheme}>
      <CssBaseline />
      <Router>
        <Routes>
          <Route path="/" element={<VulnerabilityDashboard />} />
          <Route path="/vulnerability/:cveId" element={<VulnerabilityDetailsPage />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
}

export default App;
