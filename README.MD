# Snap API QR Gateway Test _(via Paydia API Gateway)_

A minimal service for **testing Snap’s “create QR” flow** through the Paydia Gateway.  
It spins up a PHP + Nginx stack in Docker and lets you hit a single endpoint that proxies your request to Paydia’s SNAP API.

---

## 📚 Background

- **Snap API** is Paydia’s interface for QRIS transactions.  
- The **`createQrMpm`** endpoint (QR MPM generation) requires both **asymmetric** and **symmetric** signatures.  
- This repo wraps the entire flow in a simple gateway so you can focus on end-to-end testing.

---

## ⚙️ Prerequisites

I was using docker compose to run this so i dont need to install php in my local machine.

| **Docker** | <https://docs.docker.com/get-docker/> 

| **Docker Compose** | <https://docs.docker.com/compose/install/>

Make sure Docker Desktop (or Docker Engine) is running before continuing.

---

## 🔑 One-time Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/denieskresna/paydia-gateway-php.git
   cd your-repo
   ```
2. **Generate a PKCS#8 private key**

   Follow the official guide:  
   <https://snap-docs.paydia.id/snap-introduction/snap-signature/#asymmetric-key-generation>

   Save the resulting file in: `src/pkcs8_rsa_private_key.pem`
3. **Create your `.env` file**

   ```bash
   cp src/.env.example src/.env
   ```
   Open src/.env and set the actual values:
   ```text
   SNAP_HOST=https://api.paydia.co.id
   SNAP_QR_URL=/snap/v1.0/qr/qr-mpm-generate
   SNAP_TOKEN_URL=/snap/v1.0/access-token/b2b
   CLIENT_ID=your_client_id
   SECRET_KEY=your_secret_key
   PARTNER_ID=your_client_id # since the partner id in paydia use client id
   CHANNEL_ID=your_channel_id
   MERCHANT_ID=your_merchant_id
   DEBUG_MODE=TRUE   # optional
   ```

---

## 🚀 Use the Service
1. **Run docker service**
   ```bash
   docker compose up -d           # builds (if needed) and starts in detached mode
   ```
2. **Test the endpoint**
   ```curl
   curl --location 'http://localhost:4444/api/create-qr-gateway' \
   --header 'Content-Type: application/json' \
   --data '{
     "partner_reference_no": "1234DeniesTest001",
     "amount": 15000,
     "validity_period": "2025-06-10 10:00:00"
   }'
   ```

---

## 📝 License
- no license for now