const express = require('express');
const router = express.Router();
const {
  register,
  login,
  getMe
} = require('../controllers/AuthController');
const {
  verifyOTP,
  resendOTP
} = require('../controllers/otpController');
const verifyToken = require('../utils/verifyToken');

// Authentication routes
router.post('/register', register);
router.post('/login', login);
router.get('/me', verifyToken, getMe);

// OTP routes
router.post('/verify-otp', verifyOTP);
router.post('/resend-otp', resendOTP);

module.exports = router;