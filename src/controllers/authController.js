const db = require('../config/db');
const generateOtp = require('../utils/generateOtp');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');

exports.requestOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ ok: false, message: 'Email is required' });

    try {
        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await db.query('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt]);

        await sendEmail(email, 'Your RMC+ OTP', `Your OTP is ${otp}. Valid for 10 minutes.`);

        res.json({ ok: true, message: 'OTP sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
};

exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ ok: false, message: 'Email and OTP are required' });

    try {
        const [rows] = await db.query(
            'SELECT * FROM otps WHERE email = ? AND otp = ? AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
            [email, otp]
        );

        if (rows.length === 0) {
            return res.status(400).json({ ok: false, message: 'Invalid or expired OTP' });
        }

        // Mark OTP as used
        await db.query('UPDATE otps SET used = TRUE WHERE id = ?', [rows[0].id]);

        // Check if user exists
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        let user = users[0];
        let isNewUser = false;

        if (!user) {
            // Create placeholder user or just return isNewUser
            // The spec says "if new user, collect profile".
            // We can create the user record now or wait until profile submission.
            // Let's create a basic record to get an ID.
            const [result] = await db.query('INSERT INTO users (email) VALUES (?)', [email]);
            const [newUser] = await db.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
            user = newUser[0];
            isNewUser = true;
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.json({ ok: true, isNewUser, token, user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
};
