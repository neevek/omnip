import { useState, SyntheticEvent } from 'react'
import { Box, Tab, Typography } from '@mui/material'
import TabContext from '@mui/lab/TabContext';
import TabList from '@mui/lab/TabList';
import TabPanel from '@mui/lab/TabPanel';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import ProxyServer from './ProxyServer'
import QuicTunnel from './QuicTunnel'
import Stats from './Stats'
import './App.css'

const darkTheme = createTheme({
  typography: {
    fontSize: 11,
    h3: {
      fontStyle: 'italic',
    }
  },
  palette: {
    mode: 'dark',
  },
});

function App() {
  const [value, setValue] = useState('1');
  const handleChange = (_event: SyntheticEvent, newValue: string) => {
    setValue(newValue);
  };

  return (
  <ThemeProvider theme={darkTheme}>
   <CssBaseline />
   <Typography variant="h3" align='center'>Omnip</Typography>
    <Box sx={{ width: '100%', typography: 'body1' }}>
      <TabContext value={value}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <TabList onChange={handleChange} centered>
            <Tab label="Proxy Server" value="1" />
            <Tab label="QUIC Tunnel" value="2" />
            <Tab label="Stats" value="3" />
          </TabList>
        </Box>
        <TabPanel value="1"><ProxyServer /></TabPanel>
        <TabPanel value="2"><QuicTunnel /></TabPanel>
        <TabPanel value="3"><Stats /></TabPanel>
      </TabContext>
    </Box>
  </ThemeProvider>
  )
}

export default App
