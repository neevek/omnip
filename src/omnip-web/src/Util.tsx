import { Typography, Paper } from '@mui/material'

export const fetchData = async (url: string) => {
  try {
    const resp = await fetch(url);
    const json = await resp.json();
    return json.data;
  } catch (err) {
    console.log("failed to fetch data from url: " + url);
  }
}

export const postData = async (api: string, data: any) => {
  const requestOptions = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: data })
  };
  return await fetch(api, requestOptions);
}

export interface MessageProps {
  isError: boolean,
  text: string
}

const Message = (props: MessageProps) => {
  return (
    <Typography variant="body1" style={{ color: props.isError ? "#f00" : "#0f0" }}>{props.text}</Typography>
  )
}

export const MessagePanel = (props: any) => {
  return (
    props.visible &&
    <Paper elevation={6} style={{ padding: 12 }}>
      {
        props.messages.map((m: MessageProps, index: number) => 
          <Message key={index} isError={m.isError} text={m.text} />
        )
      }
    </Paper>
  )
}
