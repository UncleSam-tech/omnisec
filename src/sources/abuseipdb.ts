import axios from 'axios';
import https from 'https';
import dns from 'dns';

const customAgent = new https.Agent({
  lookup: (hostname, options, callback) => {
    if (hostname === 'api.abuseipdb.com') {
      if (typeof options === 'object' && options.all) {
        (callback as any)(null, [{ address: '104.26.13.38', family: 4 }]);
      } else {
        (callback as any)(null, '104.26.13.38', 4);
      }
    } else {
      (dns as any).lookup(hostname, options, callback);
    }
  }
});

export async function fetchAbuseIPDB(ip: string, apiKey?: string) {
  if (!apiKey) return null;
  try {
    const response = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90
      },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      httpsAgent: customAgent,
      timeout: 10000 
    });
    return response.data?.data || null;
  } catch (err: any) {
    if (axios.isAxiosError(err)) {
      if (err.response?.status === 404 || err.response?.status === 422) return null; 
      if (err.response?.status === 401 || err.response?.status === 429) {
         console.warn("AbuseIPDB API key invalid or rate-limited", err.message);
         return null; 
      }
    }
    console.warn("AbuseIPDB Fetch Error:", err.message);
    return null;
  }
}
