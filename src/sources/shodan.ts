import axios from 'axios';

export async function fetchShodan(ip: string, apiKey?: string) {
  if (!apiKey) return null;
  try {
    const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, {
      timeout: 15000 
    });
    return response.data;
  } catch (err: any) {
    if (axios.isAxiosError(err)) {
      if (err.response?.status === 404) return null; 
      if (err.response?.status === 401 || err.response?.status === 403) {
        throw new Error(`Shodan API key is explicitly invalid or rate-limited.`);
      }
    }
    console.warn("Shodan Fetch Error:", err.message);
    return null;
  }
}
