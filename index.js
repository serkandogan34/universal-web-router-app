// index.js
const express = require('express');
const requestIp = require('request-ip');
const useragent = require('useragent');
const axios = require('axios');
const helmet = require('helmet');
const httpProxy = require('http-proxy');

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 3000;

// ÇOK ÖNEMLİ: Coolify'daki ortam değişkenleri
const N8N_LOG_WEBHOOK = process.env.N8N_LOG_WEBHOOK;
const IP_GEOLOCATION_API_KEY = process.env.IP_GEOLOCATION_API_KEY;
const ROUTER_API_KEY = process.env.ROUTER_API_KEY; // Router için API anahtarı

// Hedef siteleriniz ve yönlendirme adresleri
const TARGET_DOMAINS = {
    'feroxil.shop.store': 'http://feroxil-frontend-app-internal:80',
    'api.feroxil.shop.store': 'http://feroxil-backend-api-internal:3000'
};

// IP Geolocation API'sini kullanması gereken domainler
const GEO_API_DOMAINS = ['feroxil.shop.store'];

app.use(helmet());
app.use(express.json());
app.use(requestIp.mw());

// Kimlik doğrulama middleware'i
app.use(async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey || apiKey !== ROUTER_API_KEY) {
        console.warn(`🚨 Geçersiz veya eksik API anahtarı ile istek geldi.`);
        return res.status(401).send('Yetkilendirme hatası!');
    }
    
    next();
});

app.use(async (req, res, next) => {
    const userIP = req.clientIp || req.ip;
    const agent = useragent.parse(req.headers['user-agent']);
    const host = req.headers['host'];

    if (!TARGET_DOMAINS[host]) {
        return res.status(404).send('Not Found');
    }

    if (agent.family.toLowerCase().includes('bot') || agent.family.toLowerCase().includes('spider')) {
        console.warn(`🚫 Bot isteği engellendi: IP ${userIP}`);
        return res.status(403).send('🤖 Botlara erişim yok.');
    }

    try {
        let geoData = {};

        if (GEO_API_DOMAINS.includes(host)) {
            const ipGeoResponse = await axios.get(`https://api.ipgeolocation.io/v1/ipgeo?apiKey=${IP_GEOLOCATION_API_KEY}&ip=${userIP}`);
            geoData = ipGeoResponse.data;

            if (geoData.security.is_proxy || geoData.security.is_bot || geoData.security.threat_score > 50) {
                console.warn(`🚫 Şüpheli trafik engellendi: IP ${userIP}`);
                return res.status(403).send('Botlara veya şüpheli trafiğe erişim yok.');
            }
        }

        const logData = {
            ip: userIP,
            host: host,
            userAgent: req.headers['user-agent'],
            zamanDamgasi: new Date().toISOString(),
            konumBilgisi: geoData.location || {},
            agBilgisi: geoData.network || {},
            guvenlikBilgisi: geoData.security || {},
        };

        if (N8N_LOG_WEBHOOK) {
            axios.post(N8N_LOG_WEBHOOK, logData).catch(err => console.error('🚨 N8N log hatası:', err.message));
        }

        proxy.web(req, res, { target: TARGET_DOMAINS[host] });
    } catch (error) {
        console.error('🚨 Sunucu Yönlendirme Hatası:', error.message);
        res.status(500).send('Sunucuda bir hata oluştu!');
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Middleware router ${PORT} portunda çalışıyor.`);
});
