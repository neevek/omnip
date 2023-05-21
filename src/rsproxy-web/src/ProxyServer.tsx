import { useState, BaseSyntheticEvent, useEffect } from 'react'
import { Paper, ToggleButtonGroup, ToggleButton, Button, FormControl, TextField, Stack } from '@mui/material'
import { fetchData, postData } from './Util'

function ProxyServer() {
  const [proxyAddr, setProxyAddr] = useState("");
  const [dotServer, setDotServer] = useState("");
  const [nameServers, setNameServers] = useState("");
  const [globalProxy, setGlobalProxy] = useState(false)

  const loadData = async () => {
    const serverState = await fetchData("/api/server_state");
    if (serverState) {
      setGlobalProxy(serverState.prefer_upstream);
    }

    const serverConfig = await fetchData("/api/proxy_server_config");
    if (serverConfig) {
      setProxyAddr(serverConfig.server_addr);
      setDotServer(serverConfig.dot_server);
      setNameServers(serverConfig.name_servers);
    }
  };

  useEffect(() => {
    loadData()
  }, []);

  const handleChangeProxyMode = async (
    _event: React.MouseEvent<HTMLElement>,
    mode: boolean,
  ) => {
    if (mode != null) {
      setGlobalProxy(mode);
      postData("/api/prefer_upstream", mode);
    }
  };

  const handleApplyChanges = async (_event: BaseSyntheticEvent) => {
    const config = {
      server_addr: "",  // this won't be updated
      dot_server: dotServer,
      name_servers: nameServers,
    };

    await postData("/api/update_proxy_server_config", config);
  };

  return (
    <FormControl sx={{ mt: 1, minWidth: "100%" }} >
      <Stack spacing="0.5rem">
        <TextField id="proxy-addr" label="Proxy Address" variant="filled" value={proxyAddr} disabled helperText="e.g. http://0.0.0.0:8080, socks5://0.0.0.0:8080, or leave out the protocol to support both HTTP and SOCKS proxy" />
        <TextField id="dot-server" label="DoT Server" variant="filled" value={dotServer} onChange={(e) => setDotServer(e.target.value)} helperText="e.g. dns.google, dot.pub" />
        <TextField id="name-servers" label="Name Servers" variant="filled" value={nameServers} onChange={(e) => setNameServers(e.target.value)} helperText="e.g. 8.8.8.8,1.1.1.1" />

        <ToggleButtonGroup
          color="primary"
          value={globalProxy}
          onChange={handleChangeProxyMode}
          exclusive
          size='small'
          fullWidth>
          <ToggleButton value={false}>Smart Proxy</ToggleButton>
          <ToggleButton value={true}>Global Proxy</ToggleButton>
        </ToggleButtonGroup>

        <Paper elevation={6} style={{ padding: 12 }}>Smart Proxy is applicable only when QUIC tunnel is enabled.</Paper>

        <Button variant="outlined" onClick={handleApplyChanges} fullWidth>Apply Changes</Button>
      </Stack>
    </FormControl>
  )
}

export default ProxyServer
