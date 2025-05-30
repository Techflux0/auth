const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const validator = require('validator');
const crypto = require('crypto'); 
// const { generateOTP } = require('../utils/generateOTP');
// const { sendEmail } = require('../utils/sendEmail');

// Password strength validation
const isStrongPassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return password.length >= minLength && 
         hasUpperCase && 
         hasLowerCase && 
         hasNumbers && 
         hasSpecialChars;
};

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
};

const generateOTP = () => {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
};

const sendEmail = async (to, subject, text) => {
  try {
    if (!to || !validator.isEmail(to)) {
      throw new Error('Invalid recipient email: ' + to);
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.verify();

    const mailOptions = {
      from: `Trivia App <${process.env.EMAIL_USER}>`,
      to: to, 
      subject: subject,
      text: text,
      html: `<p>${text.replace(/\n/g, '<br>')}</p>`
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent to', to);
    return info;
  } catch (error) {
    console.error('Email send error:', error);
    throw error; 
  }
};


// Register user
const register = async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'
      });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ 
        message: existingUser.username === username ? 
          'Username already taken' : 'Email already registered'
      });
    }

    // Create user
    const user = new User({ username, email, password });

    const otp = generateOTP();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // 10 minutes expiry

    user.otp = { code: otp, expiresAt: otpExpiry };
    await user.save();

    // Send OTP email
    await sendEmail(
      email,
      'Your Trivia App Verification Code',
      `Hi ${username},\n\nYour OTP is: ${otp}\n\nIt will expire in 10 minutes.`
    );

    // Create token
    const token = jwt.sign(
      { id: user._id, username, email, userType: user.userType },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username,
        email,
        userType: user.userType,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({ message: 'Username/email and password are required' });
    }

    // Find user by username or email
    const user = await User.findOne({
      $or: [
        { username: usernameOrEmail },
        { email: usernameOrEmail }
      ]
    }).select('+password');

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check if verified
    if (!user.isVerified) {
      return res.status(400).json({ 
        message: 'Please verify your email first',
        email: user.email
      });
    }

    // Create token
    const token = jwt.sign(
      { 
        id: user._id,
        username: user.username,
        email: user.email,
        userType: user.userType
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        userType: user.userType,
        subscription: user.subscription,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

// Get current user
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -otp');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error fetching user' });
  }
};

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    // 1. Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Email not found' });
    }

    // 2. Generate and save OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetPasswordOtp = otp;
    user.resetPasswordExpire = Date.now() + 600000; // 10 minutes
    await user.save();

    // 3. Log the stored values for debugging
    console.log(`Stored OTP: ${otp} for email: ${email}`);
    console.log(`Expires at: ${new Date(user.resetPasswordExpire)}`);

    // 4. Send email
    await sendEmail(
      user.email,
      'Password Reset OTP',
      `Your OTP is: ${otp} (expires in 10 minutes)`
    );

    res.status(200).json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Reset request error:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
};

const verifyResetOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ 
      email,
      resetPasswordOtp: otp,
      resetPasswordExpire: { $gt: Date.now() }
    });

  
    if (!user) {
      const expiredUser = await User.findOne({ email });
      console.log('Database OTP:', expiredUser?.resetPasswordOtp);
      console.log('Current time:', new Date());
      console.log('Expiry time:', expiredUser?.resetPasswordExpire 
        ? new Date(expiredUser.resetPasswordExpire) 
        : 'Not set');
    }

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const tempToken = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '10m' }
    );

    res.status(200).json({ 
      message: 'OTP verified',
      tempToken 
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
};



const resetPassword = async (req, res) => {
  try {
    const { tempToken, newPassword } = req.body;

    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);
    user.password = newPassword;
    user.resetPasswordOtp = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(200).json({ message: 'Password updated' });
  } catch (error) {
    console.error('Reset error:', error);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
};

//Make sure to export appro sucker
module.exports = {
  register,
  login,
  getMe,
  requestPasswordReset,
  verifyResetOtp,
  resetPassword
};