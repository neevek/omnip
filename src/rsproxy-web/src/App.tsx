import { useState, BaseSyntheticEvent, useEffect } from 'react'
import { Paper, ToggleButtonGroup, ToggleButton, Button, Typography, FormControl, MenuItem, TextField, Stack, Container } from '@mui/material'
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
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
  const [proxyAddr, setProxyAddr] = useState("");
  const [upstream, setUpstream] = useState("");
  const [password, setPassword] = useState("");
  const [certPath, setCertPath] = useState("");
  const [idleTimeout, setIdleTimeout] = useState(120000);
  const [retryInterval, setRetryInterval] = useState(5000);
  const [cipher, setCipher] = useState("");
  const [dotServer, setDotServer] = useState("");
  const [nameServers, setNameServers] = useState("");
  const [globalProxy, setGlobalProxy] = useState(false)
  const [tunnelState, setTunnelState] = useState("NotConnected")
  const [logMessages, setLogMessages] = useState("")
  // const [startButtonDisabled, setStartButtonDisabled] = useState(false)
  // const [stopButtonDisabled, _setStopButtonDisabled] = useState(false)

  const handleApplyChanges = (event: BaseSyntheticEvent) => {
    console.log(event.target);
    // setStartButtonDisabled(true);
  };

  const fetchData = async (url: string) => {
    try {
      const resp = await fetch(url);
      const json = await resp.json();
      return json.data;
    } catch (err) {
      console.log("failed to fetch data from url: " + url);
    }
  }

  const handleChangeProxyMode = async (
    _event: React.MouseEvent<HTMLElement>,
    mode: boolean,
  ) => {
    if (mode != null) {
      setGlobalProxy(mode);
      const requestOptions = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: mode })
      };
      await fetch("/api/prefer_upstream", requestOptions);
    }
  };

  useEffect(() => {
    const update = async () => {
      const serverState = await fetchData("/api/server_state");
      if (serverState) {
        setGlobalProxy(serverState.prefer_upstream);
        setTunnelState(serverState.tunnel_state);
        setLogMessages(serverState.log_messages);
      }

      const serverConfig = await fetchData("/api/server_config");
      if (serverConfig) {
        setProxyAddr(serverConfig.server_addr);
        setUpstream(serverConfig.upstream_addr);
        setPassword(serverConfig.password);
        setCertPath(serverConfig.cert_path);
        setIdleTimeout(serverConfig.idle_timeout);
        setRetryInterval(serverConfig.retry_interval);
        setCipher(serverConfig.cipher);
        setDotServer(serverConfig.dot_server);
        setNameServers(serverConfig.name_servers);
      }
    };

    const interval = setInterval(() => {
      update();
    }, 3000);

    return () => clearInterval(interval);
  }, [])

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Typography variant="h3" align='center'>rsproxy</Typography>
      <Container maxWidth="sm">
        <FormControl sx={{ mt: 2, minWidth: "100%" }} >
          <Stack spacing="0.5rem">
            <TextField id="proxy-addr" label="Proxy Address" variant="filled" value={proxyAddr} disabled />
            <TextField id="upstream" label="Upstream" variant="filled" value={upstream} onChange={(e) => setUpstream(e.target.value)} />
            <TextField id="password" label="Password" type='password' variant="filled" value={password} onChange={(e) => setPassword(e.target.value)}/>
            <TextField id="cert-path" label="Path to SSL Certificate" variant="filled" value={certPath} onChange={(e) => setCertPath(e.target.value)}/>
            <TextField id="idle-timeout" label="Idle Timeout (ms)" type='number' variant="filled" value={idleTimeout} onChange={(e) => setIdleTimeout(parseInt(e.target.value))}/>
            <TextField id="retry-interval" label="Retry Interval (ms)" type='number' variant="filled" value={retryInterval} onChange={(e) => setRetryInterval(parseInt(e.target.value))}/>

            <TextField
              value={cipher}
              label="Cipher"
              select
              onChange={(e) => setDotServer(e.target.value)} 
              size='small'
            >
              <MenuItem value="chacha20-poly1305">chacha20-poly1305</MenuItem>
              <MenuItem value="aes-256-gcm">aes-256-gcm</MenuItem>
              <MenuItem value="aes-128-gcm">aes-128-gcm</MenuItem>
            </TextField>

            <TextField id="dot-server" label="DoT Server" variant="filled" value={dotServer} onChange={(e) => setDotServer(e.target.value)} />
            <TextField id="name-servers" label="Name Servers" variant="filled" value={nameServers} onChange={(e) => setNameServers(e.target.value)} />

            <ToggleButtonGroup
              color="primary"
              value={globalProxy}
              onChange={handleChangeProxyMode}
              exclusive
              size='small'
              fullWidth
            >
              <ToggleButton value={false}>Smart Proxy</ToggleButton>
              <ToggleButton value={true}>Global Proxy</ToggleButton>
            </ToggleButtonGroup>

              <Button variant="outlined" onClick={handleApplyChanges} fullWidth>Apply Changes</Button>

            <Paper elevation={6} style={{ padding: 12 }}>{tunnelState}</Paper>
            <Paper elevation={6} style={{ padding: 12, color: "#0f0" }}>{logMessages}</Paper>

          </Stack>
        </FormControl>
      </Container>
    </ThemeProvider>
  )
}

export default App
