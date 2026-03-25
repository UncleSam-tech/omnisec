import axios from 'axios';
import https from 'https';
import dns from 'dns';

const customAgent = new https.Agent({
    lookup: (hostname: string, options: any, callback: any) => {
        if (hostname === 'api.greynoise.io') {
            if (typeof options === 'object' && options.all) {
                callback(null, [{ address: '32.193.91.206', family: 4 }]);
            } else {
                callback(null, '32.193.91.206', 4);
            }
        } else {
            dns.lookup(hostname, options, callback);
        }
    }
});

export async function fetchGreyNoise(ip: string, apiKey?: string) {
    if (!apiKey) return null;
    try {
        const response = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
            headers: {
                'key': apiKey,
                'Accept': 'application/json'
            },
            httpsAgent: customAgent,
            timeout: 10000
        });
        return response.data;
    } catch (err: any) {
        if (axios.isAxiosError(err)) {
            if (err.response?.status === 404) return null; 
            if (err.response?.status === 401 || err.response?.status === 429) {
                console.warn("GreyNoise API key invalid or rate-limited", err.message);
                return null;
            }
        }
        console.warn("GreyNoise Fetch Error:", err.message);
        return null;
    }
}
