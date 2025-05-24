const User = require('../models/User');

// Verify OTP
exports.verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Check if OTP exists and is not expired
        if (!user.otp || user.otp.expiresAt < new Date()) {
            return res.status(400).json({ message: 'OTP expired or invalid' });
        }

        // Check if OTP matches
        if (user.otp.code !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        // Mark user as verified and clear OTP
        user.isVerified = true;
        user.otp = undefined;
        await user.save();

        res.json({ message: 'Email verified successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
};

// Resend OTP
exports.resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + parseInt(process.env.OTP_EXPIRY_MINUTES));

        user.otp = {
            code: otp,
            expiresAt: otpExpiry
        };

        await user.save();

        // Send OTP email
        await sendEmail(
            email,
            'Your New Trivia App Verification OTP',
            `Your new OTP is: ${otp}. It will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.`
        );

        res.json({ message: 'New OTP sent successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
};