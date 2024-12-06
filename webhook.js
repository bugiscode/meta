require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();

// Konfigurasi dari file .env
const PORT = process.env.APP_PORT || 3000;
const SECRET = process.env.APP_SECRET;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const WHITELISTED_IPS = process.env.WHITELISTED_IPS
    ? process.env.WHITELISTED_IPS.split(',')
    : [];

if (!SECRET || !VERIFY_TOKEN) {
    console.error('ERROR: APP_SECRET and VERIFY_TOKEN must be set in the environment.');
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

// Middleware untuk memeriksa IP whitelist
app.use((req, res, next) => {
    const clientIp = req.ip.replace('::ffff:', ''); // Hapus prefiks IPv6 jika ada
    if (!WHITELISTED_IPS.includes(clientIp)) {
        console.error(`Unauthorized access attempt from IP: ${clientIp}`);
        return res.status(403).send('Access forbidden: Your IP is not allowed.');
    }
    next();
});

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
        const signature = req.headers['x-hub-signature-256'];

        if (!signature) {
            console.error('Signature missing in request.');
            return res.status(403).send('Forbidden');
        }

        const hash = `sha256=${crypto
            .createHmac('sha256', SECRET)
            .update(JSON.stringify(req.body))
            .digest('hex')}`;

        if (signature !== hash) {
            console.error('Signature mismatch.');
            return res.status(403).send('Invalid signature.');
        }

        // Proses payload webhook
        const body = req.body;
        console.log('Webhook payload:', JSON.stringify(body, null, 2));

        res.status(200).send('Event received');
    } catch (err) {
        console.error('Error processing webhook:', err);
        res.status(500).send('Internal server error');
    }
});

// Jalankan server
app.listen(PORT, () => {
    console.log(`Webhook server running on port ${PORT}`);
    console.log(`Whitelisted IPs: ${WHITELISTED_IPS.join(', ')}`);
});
