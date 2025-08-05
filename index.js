const express = require('express');
const axios = require('axios');
const httpProxy = require('http-proxy');

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 3000;

// ÇOK ÖNEMLİ: Coolify'daki ortam değişkenleri
const N8N_LOG_WEBHOOK = process.env.N8N_LOG_WEBHOOK;
const IP_GEOLOCATION_API_KEY = process.env.IP_GEOLOCATION_API_KEY;

// Hedef siteleriniz ve yönlendirme adresleri
const TARGET_DOMAINS = {
    'feroxil.shop.store': 'http://feroxil-frontend-app-internal:80', // Hedef sunucu adresinizi buraya girin
    'site2.com': 'http://site2-app-internal:80', // Örnek hedef
};

// IP Geolocation API'sini kullanması gereken domainler
const GEO_API_DOMAINS = ['feroxil.shop.store'];

app.use(async (req, res, next) => {
    const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const host = req.headers['host'];

    if (!TARGET_DOMAINS[host]) {
        return res.status(404).send('Not Found');
    }

    let geoData = {};

    if (GEO_API_DOMAINS.includes(host)) {
        try {
            const ipGeoResponse = await axios.get(`https://api.ipgeolocation.io/v1/ipgeo?apiKey=${IP_GEOLOCATION_API_KEY}&ip=${userIP}`);
            geoData = ipGeoResponse.data;

            if (geoData.security.is_proxy || geoData.security.is_bot || geoData.security.threat_score > 50) {
                console.warn(`🚫 Şüpheli trafik engellendi: IP ${userIP}`);
                return res.status(403).send('Botlara veya şüpheli trafiğe erişim yok.');
            }
        } catch (error) {
            console.error('🚨 ipgeolocation API hatası:', error.message);
        }
    }

    if (N8N_LOG_WEBHOOK) {
        const logData = {
            ip: userIP,
            host: host,
            userAgent: userAgent,
            zamanDamgasi: new Date().toISOString(),
            konumBilgisi: geoData.location || {},
            agBilgisi: geoData.network || {},
            guvenlikBilgisi: geoData.security || {},
        };
        axios.post(N8N_LOG_WEBHOOK, logData).catch(err => console.error('🚨 n8n log hatası:', err.message));
    }

    proxy.web(req, res, { target: TARGET_DOMAINS[host] });
});

app.listen(PORT, () => {
    console.log(`🚀 Router sunucusu ${PORT} portunda çalışıyor.`);
});
