// File: login.js (atau config/login.js)

// IMPORTS
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

// Load .env
require('dotenv').config({
    path: path.resolve(__dirname, '..', '.env')
});

const JWT_SECRET = process.env.JWT_SECRET;

// EXPORT FUNCTION (MENERIMA `con`)
module.exports = (con) => {

    if (!JWT_SECRET) {
        throw new Error("FATAL ERROR: JWT_SECRET not defined.");
    }

    // =====================================================
    // 🔐 LOGIN
    // =====================================================
    router.post('/login', async (req, res) => {

        const { email, password } = req.body;

        try {
            const result = await con.query(
                "SELECT client_id, name, password, email FROM client WHERE email = $1",
                [email]
            );

            const client = result.rows[0];
            if (!client) {
                return res.status(401).json({ success: false, message: "Email atau password salah." });
            }

            // Password kamu saat ini plaintext → dibiarkan dulu
            const passwordMatch = (password === client.password);

            if (!passwordMatch) {
                return res.status(401).json({ success: false, message: "Email atau password salah." });
            }

            const payload = {
                id: client.client_id,
                email: client.email,
                name: client.name
            };

            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

            res.status(200).json({
                success: true,
                message: "Login berhasil",
                token,
                client_id: client.client_id,
                name: client.name
            });

        } catch (err) {
            console.error(err);
            res.status(500).json({ success: false, message: "Terjadi kesalahan server." });
        }
    });

    // =====================================================
    // 🔥 FORGOT PASSWORD → KIRIM OTP
    // =====================================================
    router.post('/forgot-password', async (req, res) => {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Email harus diisi." });
        }

        try {
            // Cek apakah email ada
            const check = await con.query(
                "SELECT * FROM client WHERE email = $1",
                [email]
            );

            if (check.rows.length === 0) {
                return res.status(404).json({ error: "Email tidak ditemukan." });
            }

            // Generate OTP 6 digit
            const otp = Math.floor(100000 + Math.random() * 900000);
            const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 menit

            // Simpan OTP + expiry
            await con.query(
                "UPDATE client SET otp = $1, otp_expiry = $2 WHERE email = $3",
                [otp, expiry, email]
            );

            // Kirim email
            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            await transporter.sendMail({
                from: `"Ravello App" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: "Kode OTP Reset Password",
                text: `Kode OTP Anda adalah ${otp}. Berlaku 5 menit.`
            });

            res.json({ message: "OTP berhasil dikirim ke email Anda." });

        } catch (err) {
            console.error("OTP Error:", err);
            res.status(500).json({ error: "Terjadi kesalahan server." });
        }
    });

    return router;
};
