const http = require('http');
const req = http.request('http://localhost:3000/sse', { method: 'GET' }, (res) => {
  let endpointUrl;
  res.on('data', (chunk) => {
    const data = chunk.toString();
    console.log('SSE GET DATA:', data);
    if (data.includes('endpoint')) {
        const lines = data.split('\n');
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                endpointUrl = line.replace('data: ', '');
                console.log('Got endpointUrl from SSE:', endpointUrl);
                let sessionId = new URL(endpointUrl, 'http://localhost:3000').searchParams.get('sessionId');
                if (!sessionId && endpointUrl.includes('sessionId=')) {
                    sessionId = endpointUrl.split('sessionId=')[1].split('&')[0];
                }
                console.log('Extracted sessionId:', sessionId);
                
                const postReq = http.request('http://localhost:3000/messages?sessionId=' + sessionId, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                }, (postRes) => {
                    let body = '';
                    postRes.on('data', c => body += c);
                    postRes.on('end', () => console.log('POST Response:', postRes.statusCode, body));
                    setTimeout(() => process.exit(0), 100);
                });
                postReq.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }));
                postReq.end();
            }
        }
    }
  });
});
req.end();
