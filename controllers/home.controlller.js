const express = require('express');
const home = express.Router();
const users = require("../models/users.model");
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

require('dotenv').config();

const transporter = nodemailer.createTransport({
    secure: true,
    host: 'smtp.gmail.com', 
    port: 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


home.post("/forget-password", async (req, res) => {
    try {
        const { username } = req.body;

        const user = await users.findOne({ username });
        if (!user) {
            return res.status(404).json({
                message: "User not found",
                success: false
            });
        }

        
        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // Token valid for 1 hour

       
        user.resetpasswordtoken = token;
        user.resetpasswordexpires = expires;
        await user.save();

       
        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
        


        
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset',
            text: `Hello, ${user.username}. You requested a password reset. Click the link below to reset your password: \n\n${resetLink}\n\nThis link will expire in one hour.`,
            html:`<p>Hello, ${user.username}. You requested a password reset.</p>
            <p>Click the link below to reset your password:</p>
            <a href="${resetLink}">Reset Your Password</a>
            <p>If you did not request this, please ignore this email. The link will expire in 1 hour for security reasons.</p>`
        };

        
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({
                    message: 'Failed to send email',
                    success: false,
                    error: error.message
                });
            }

            
            return res.status(200).json({
                message: `Password reset email sent successfully`,
                success: true
            });
        });
    } catch (error) {
        res.status(503).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});


home.get("/verify-token/:token", async (req, res) => {
    try {
        const { token } = req.params;

        
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() } 
        });

        if (!user) {
            return res.status(400).json({
                message: "Invalid or expired token",
                success: false
            });
        }

        
        res.status(200).json({
            message: "Token is valid",
            success: true   
        });

    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});


home.post("/reset-password", async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                message: "Invalid or expired token",
                success: false
            });
        }

        
        const saltRounds = 10;
        user.password = await bcrypt.hash(newPassword, saltRounds);

        user.resetpasswordtoken = undefined;
        user.resetpasswordexpires = undefined;

        await user.save();

        
        res.status(200).json({
            message: "Password successfully reset",
            success: true
        });

    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});

module.exports = home;
