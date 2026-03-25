import axios from 'axios';

export async function fetchPulsedive(ip: string, apiKey?: string) {
    if (!apiKey) return null;
    try {
        const response = await axios.get(`https://pulsedive.com/api/info.php`, {
            params: {
                indicator: ip,
                key: apiKey,
                pretty: 1
            },
            timeout: 10000
        });
        
        if (response.data?.error) {
            if (response.data.error.includes("not found")) return null;
            console.warn("Pulsedive API Error:", response.data.error);
            return null;
        }
        return response.data;
    } catch (err: any) {
        if (axios.isAxiosError(err)) {
            if (err.response?.status === 404) return null;
            if (err.response?.status === 401 || err.response?.status === 429) {
                console.warn("Pulsedive API key invalid or rate-limited", err.message);
                return null;
            }
        }
        console.warn("Pulsedive Fetch Error:", err.message);
        return null;
    }
}
