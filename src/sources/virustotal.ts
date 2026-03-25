import axios from 'axios';

export async function fetchVirusTotal(ip: string, apiKey?: string) {
  if (!apiKey) return null;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      },
      timeout: 15000 
    });
    return response.data;
  } catch (err: any) {
    if (axios.isAxiosError(err)) {
      if (err.response?.status === 404) return null; // Not found on VT = no threat data
      if (err.response?.status === 401 || err.response?.status === 403) {
        throw new Error(`VirusTotal API key is explicitly invalid or rate-limited.`);
      }
    }
    console.warn("VT Fetch Error:", err.message);
    return null; // Gracefully degrade if VT fails, allowing Shodan to carry the load
  }
}
