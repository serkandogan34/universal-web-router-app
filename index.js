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

// Hedef uygulamaları tanımla
const TARGET_APPLICATIONS = {
    'feroxil.shop.store': 'http://feroxil-frontend-app-internal:80',
    'api.feroxil.shop.store': 'http://feroxil-backend-api-internal:3000'
};

app.use(helmet());
app.use(express.json());
app.use(requestIp.mw());

// GENEL TRAFİK İÇİN GÜVENLİK VE LOGLAMA
app.use(async (req, res, next) => {
    const userIP = req.clientIp;
    const agent = useragent.parse(req.headers['user-agent']);
    const domain = req.headers.host;

    if (!TARGET_APPLICATIONS[domain]) {
        return res.status(404).send('Not Found');
    }

    // Bot ve temel güvenlik kontrolü
    if (agent.family.toLowerCase().includes('bot') || agent.family.toLowerCase().includes('spider')) {
        console.warn(`🚫 Bot isteği engellendi: IP ${userIP}`);
        return res.status(403).send('🤖 Botlara erişim yok.');
    }

    try {
        const ipGeoResponse = await axios.get(`https://api.ipgeolocation.io/v1/ipgeo?apiKey=${IP_GEOLOCATION_API_KEY}&ip=${userIP}`);
        const geoData = ipGeoResponse.data;

        // Loglama verisini n8n'e gönder
        const logData = {
            ip: userIP,
            host: domain,
            userAgent: req.headers['user-agent'],
            zamanDamgasi: new Date().toISOString(),
            ...geoData,
        };

        if (N8N_LOG_WEBHOOK) {
            axios.post(N8N_LOG_WEBHOOK, logData).catch(err => console.error('🚨 N8N log hatası:', err.message));
        }

        // Şüpheli trafik kontrolü
        if (geoData.security.is_proxy || geoData.security.is_vpn || geoData.security.is_tor || geoData.security.threat_score > 50) {
            console.warn(`🚫 Şüpheli trafik engellendi: IP ${userIP}`);
            return res.status(403).send('Botlara veya şüpheli trafiğe erişim yok.');
        }

        proxy.web(req, res, { target: TARGET_APPLICATIONS[domain] });

    } catch (error) {
        console.error('🚨 Sunucu Yönlendirme Hatası:', error.message);
        res.status(500).send('Sunucuda bir hata oluştu!');
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Middleware router ${PORT} portunda çalışıyor.`);
});
