import { useState, useEffect } from 'react'
import { Button, FormControl } from '@mui/material'
import { fetchData, MessagePanel, MessageProps } from './Util'

function App() {
  const [messages, setMessages] = useState<MessageProps[]>([]);

  const loadStats = async () => {
    const stats = await fetchData("/api/stats");
    if (stats) {
      const messages = [
        { isError: false, text: "Total Tx (bytes): " + stats.total_tx_bytes },
        { isError: false, text: "Total Rx (bytes): " + stats.total_rx_bytes },
        { isError: false, text: "Ongoing Connections: " + stats.ongoing_connections },
        { isError: false, text: "Total Connections: " + stats.total_connections },
      ];
      setMessages(messages);
    }
  }

  useEffect(() => {
    loadStats()
  }, []);

  return (
    <FormControl sx={{ mt: 1, minWidth: "100%" }} >
      <MessagePanel visible={messages.length > 0} messages={messages}/>
      <Button  sx={{ mt: 2 }} variant="outlined" onClick={loadStats} fullWidth>Refresh</Button>
    </FormControl>
  )
}

export default App
