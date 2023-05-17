import { useState, BaseSyntheticEvent, useEffect } from 'react'
import { Paper, Button, FormControl, MenuItem, TextField, Stack } from '@mui/material'
import { fetchData, postData, MessagePanel, MessageProps } from './Util'

function QuicTunnel() {
  const [upstream_addr, setUpstream] = useState("");
  const [password, setPassword] = useState("");
  const [certPath, setCertPath] = useState("");
  const [idleTimeout, setIdleTimeout] = useState(120000);
  const [retryInterval, setRetryInterval] = useState(5000);
  const [cipher, setCipher] = useState("");
  const [tunnelState, setTunnelState] = useState("NotConnected");
  const [messages, setMessages] = useState<MessageProps[]>([]);

  const loadData = async () => {
    const serverState = await fetchData("/api/server_state");
    if (serverState) {
      setTunnelState(serverState.tunnel_state);
    }

    const serverConfig = await fetchData("/api/quic_tunnel_config");
    if (serverConfig) {
      setUpstream(serverConfig.upstream_addr);
      setPassword(serverConfig.password);
      setCertPath(serverConfig.cert);
      setIdleTimeout(serverConfig.idle_timeout);
      setRetryInterval(serverConfig.retry_interval);
      setCipher(serverConfig.cipher);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const updateMessage = (message: MessageProps) => {
    messages.push(message);
    setMessages([...messages]);
  }

  const updateQuicTunnelConfig = async (_event: BaseSyntheticEvent) => {
    const config = {
      upstream_addr,
      cert: certPath,
      cipher,
      password,
      idle_timeout: idleTimeout,
      retry_interval: retryInterval,
    };

    postData("/api/update_quic_tunnel_config", config)
      .then((response) => response.json())
      .then((data) => {
        if (data.code == 0) {
          updateMessage({ isError: false, text: "TunnelConfig updated!"});
        } else {
          updateMessage({ isError: true, text: data.msg });
        }

        loadData();
      })
      .catch((e) => {
        updateMessage({ isError: true, text: e.toString() });
      });
  };

  return (
    <FormControl sx={{ mt: 1, minWidth: "100%" }} >
      <Stack spacing="0.5rem">
        <TextField id="upstream_addr" label="Upstream Address" variant="filled" value={upstream_addr} onChange={(e) => setUpstream(e.target.value)} helperText="e.g. example.com:3515, 1.2.3.4:3515" />
        <TextField id="password" label="Password" type='password' variant="filled" value={password} onChange={(e) => setPassword(e.target.value)}/>
        <TextField id="cert-path" label="Path to SSL Certificate" variant="filled" value={certPath} onChange={(e) => setCertPath(e.target.value)} helperText="leave this blank if connecting to the server using domain name"/>
        <TextField id="idle-timeout" label="Idle Timeout (ms)" type='number' variant="filled" value={idleTimeout} onChange={(e) => setIdleTimeout(parseInt(e.target.value))}/>
        <TextField id="retry-interval" label="Retry Interval (ms)" type='number' variant="filled" value={retryInterval} onChange={(e) => setRetryInterval(parseInt(e.target.value))}/>

        <TextField
          value={cipher}
          label="Cipher"
          select
          onChange={(e) => setCipher(e.target.value)} 
          size='small'
        >
          <MenuItem value="chacha20-poly1305">chacha20-poly1305</MenuItem>
          <MenuItem value="aes-256-gcm">aes-256-gcm</MenuItem>
          <MenuItem value="aes-128-gcm">aes-128-gcm</MenuItem>
        </TextField>

        <Stack spacing="0.5rem" direction="row">
          <Button variant="outlined" onClick={loadData} fullWidth>Refresh</Button>
          <Button variant="outlined" onClick={updateQuicTunnelConfig} fullWidth>Apply Changes</Button>
        </Stack>

        <Paper elevation={6} style={{ padding: 12 }}>{tunnelState}</Paper>
        <MessagePanel visible={messages.length > 0} messages={messages}/>

      </Stack>
    </FormControl>
  )
}

export default QuicTunnel
