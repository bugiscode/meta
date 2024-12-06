const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const dotenv = require("dotenv");

// Tentukan lingkungan (dev/prod) dan muat file .env yang sesuai
const ENVIRONMENT = process.env.NODE_ENV || "dev";
dotenv.config({ path: `.env.${ENVIRONMENT}` });

const app = express();
const PORT = process.env.APP_PORT || 3000;
const APP_SECRET = process.env.APP_SECRET; 
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const WHITELISTED_IPS = process.env.WHITELISTED_IPS.split(",");

// Middleware untuk membaca JSON
app.use(bodyParser.json());

// Endpoint verifikasi webhook
app.get("/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode && token) {
        if (mode === "subscribe" && token === VERIFY_TOKEN) {
            console.log("Webhook verified!");
            res.status(200).send(challenge);
        } else {
            res.status(403).send("Forbidden");
        }
    }
});

// Middleware untuk memvalidasi tanda tangan
const verifySignature = (req, res, next) => {
    const signature = req.headers["x-hub-signature-256"];

    if (!signature) {
        return res.status(401).send("Signature missing");
    }

    const payload = JSON.stringify(req.body);
    const expectedSignature = `sha256=${crypto
        .createHmac("sha256", APP_SECRET)
        .update(payload)
        .digest("hex")}`;

    if (signature !== expectedSignature) {
        console.error("Invalid signature");
        return res.status(401).send("Invalid signature");
    }

    next();
};

// Middleware untuk memvalidasi IP
const verifyIP = (req, res, next) => {
    const clientIP = req.ip;

    if (!WHITELISTED_IPS.includes(clientIP)) {
        console.error(`Unauthorized IP: ${clientIP}`);
        return res.status(403).send("Unauthorized IP");
    }

    next();
};

// Endpoint untuk menerima data
app.post("/webhook", verifyIP, verifySignature, (req, res) => {
    const body = req.body;

    if (body.object) {
        console.log("Received webhook event:", JSON.stringify(body, null, 2));
        res.status(200).send("EVENT_RECEIVED");
    } else {
        res.sendStatus(404);
    }
});

app.listen(PORT, () => {
    console.log(`Webhook server is running on port ${PORT} in ${ENVIRONMENT} mode`);
});
