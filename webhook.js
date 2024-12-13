const environment = process.env.NODE_ENV || 'development';
require('dotenv').config({ path: `.env.${environment}` });
const express = require('express');
const bodyParser = require('body-parser');
const https = require('https');
const fs = require('fs');

const app = express();

// Konfigurasi dari file .env
const PORT = process.env.APP_PORT || 3100;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

if (!VERIFY_TOKEN) {
    console.error('ERROR: VERIFY_TOKEN must be set in the environment.');
    process.exit(1);
}

// Middleware untuk log level (opsional)
if (LOG_LEVEL === 'debug') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.url}`);
        next();
    });
}

// Middleware untuk body parser
app.use(bodyParser.json());

// Verifikasi Token Webhook
app.get('/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode && token === VERIFY_TOKEN) {
        console.log('Webhook verified successfully.');
        res.status(200).send(challenge);
    } else {
        console.error('Webhook verification failed.');
        res.status(403).send('Forbidden');
    }
});

// Endpoint untuk menerima webhook
app.post('/webhook', (req, res) => {
    try {
        // Langsung memproses payload webhook tanpa signature validation
        const body = req.body;
        console.log('Webhook payload:', JSON.stringify(body, null, 2));

        // Proses payload webhook
        res.status(200).send('Event received');
    } catch (err) {
        console.error('Error processing webhook:', err);
        res.status(500).send('Internal server error');
    }
});

// Opsi sertifikat SSL
const options = {
    key: fs.readFileSync('/etc/letsencrypt/live/be.omchannel.com/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/be.omchannel.com/fullchain.pem')
};

// Jalankan server HTTPS
https.createServer(options, app).listen(PORT, () => {
    console.log(`Webhook server running on https://localhost:${PORT}`);
});
