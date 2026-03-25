import axios from 'axios';

export async function fetchPulse(ip: string, apiKey?: string) {
  if (!apiKey) return null;
  try {
    const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, {
      headers: {
        'X-OTX-API-KEY': apiKey,
        'Accept': 'application/json'
      },
      timeout: 15000 
    });
    return response.data;
  } catch (err: any) {
    if (axios.isAxiosError(err)) {
      if (err.response?.status === 404) return null; 
      if (err.response?.status === 401 || err.response?.status === 403) {
        throw new Error(`Pulse OTX API key is explicitly invalid or rate-limited.`);
      }
    }
    console.warn("Pulse Fetch Error:", err.message);
    return null;
  }
}
