require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const Razorpay = require('razorpay');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { body, validationResult } = require('express-validator');

// Anti-Scraping Middleware
const blockScrapers = (req, res, next) => {
    const userAgent = req.get('User-Agent') || '';
    const blockedAgents = [
        'HTTrack', 'Wget', 'curl', 'libwww-perl', 'Python-urllib',
        'Go-http-client', 'Scrapy', 'HttpClient', 'Java'
    ];

    // Check if user agent matches any blocked agent
    const isBlocked = blockedAgents.some(agent =>
        userAgent.toLowerCase().includes(agent.toLowerCase())
    );

    if (isBlocked) {
        return res.status(403).json({
            ok: false,
            message: 'Access denied: Automated access not allowed.'
        });
    }
    next();
};
const path = require('path');
const fs = require('fs');
const adminRoutes = require('./src/routes/adminRoutes');
const bookingRoutes = require('./src/routes/bookingRoutes');
const reportRoutes = require('./src/routes/reportRoutes');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    connectTimeout: 30000, // 30 seconds for cloud DBs
    ssl: process.env.DB_SSL_CA ? {
        ca: fs.readFileSync(path.resolve(__dirname, process.env.DB_SSL_CA))
    } : undefined
});

// Test DB Connection
pool.getConnection()
    .then(conn => {
        console.log('✅ Database POOL connected successfully to', process.env.DB_HOST);
        conn.release();
    })
    .catch(err => {
        console.error('❌ Database POOL connection failed:', err);
    });

const app = express();

// FIX: REQUIRED for express-rate-limit behind Render proxy
app.set('trust proxy', 1);


// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://checkout.razorpay.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'self'", "https://api.razorpay.com"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// CORS with credentials - Support both user and admin frontends
app.use(cors({
    origin: [
        'http://localhost:5173',  // User frontend
        'http://localhost:5174',  // Admin frontend (default)
        'https://rmcplus.seris.site/',  // Admin frontend (alternate port)
        'http://localhost:5176',  // Current frontend port
        process.env.FRONTEND_URL  // Production URL
    ].filter(Boolean),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Compression for performance
app.use(compression());

// Block Scrapers
app.use(blockScrapers);

// Body parser with size limits
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser for HttpOnly cookies
app.use(cookieParser());

// Serve uploads directory (with security)
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    dotfiles: 'deny',
    index: false
}));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: 'Too many attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false
});

// General API rate limiter
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', apiLimiter);


// Bypass authentication middleware for admin (no login required)
const bypassAuth = (req, res, next) => {
    // Set a dummy admin user so routes don't fail
    req.user = {
        id: 1,
        email: 'admin@rmc.com',
        is_admin: true,
        role: 'super_admin'
    };
    next();
};

// Mount Admin Routes (NO AUTHENTICATION REQUIRED)
app.use('/api/admin', adminRoutes(pool, sendOtpMail, bypassAuth));

// Mount Booking Routes
app.use('/api/bookings', authenticateToken, bookingRoutes(pool));

// Mount Report Routes
app.use('/api/reports', reportRoutes(pool));

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads', { recursive: true, mode: 0o755 });
}

// ============================================
// DATABASE CONNECTION & AUTO-INITIALIZATION
// ============================================

// Function to initialize database
const initializeDatabase = require('./scripts/initDatabase');

// Initialize database on startup
initializeDatabase()
    .then(() => {
        console.log('✅ Database initialized successfully');
    })
    .catch(err => {
        console.error('❌ Database initialization failed:', err);
    });


// ============================================
// EMAIL CONFIGURATION
// ============================================

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ============================================
// RAZORPAY CONFIGURATION
// ============================================

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ============================================
// SECURE FILE UPLOAD CONFIGURATION
// ============================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // Generate random number filename
        const randomNum = Math.floor(1000000000 + Math.random() * 9000000000); // 10 digit random number
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${randomNum}${ext}`);
    }
});

// File filter for security
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['.pdf', '.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedMimes = ['application/pdf', 'image/jpeg', 'image/png'];

    if (allowedTypes.includes(ext) && allowedMimes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF and images allowed.'), false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB max
    }
});

// ============================================
// UTILITY FUNCTIONS
// ============================================

function generateOTP() {
    return Math.floor(10000 + Math.random() * 90000).toString();
}

async function hashOTP(otp) {
    return await bcrypt.hash(otp, 10);
}

async function verifyOTP(otp, hashedOTP) {
    return await bcrypt.compare(otp, hashedOTP);
}

function signJwt(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function setAuthCookie(res, token) {
    res.cookie('auth_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/'
    });
}

function clearAuthCookie(res) {
    res.clearCookie('auth_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    });
}

async function sendOtpMail(email, otp) {
    try {
        await transporter.sendMail({
            from: `"RMC+ Diagnostics" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your RMC+ Login OTP',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e5e5e5; border-radius: 8px;">
          <h2 style="color: #1f4179; margin-bottom: 20px;">RMC+ Login Verification</h2>
          <p style="font-size: 16px; color: #222;">Your One-Time Password (OTP) is:</p>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h1 style="color: #ee7237; font-size: 36px; letter-spacing: 8px; margin: 0;">${otp}</h1>
          </div>
          <p style="font-size: 14px; color: #666;">This OTP is valid for 10 minutes.</p>
          <p style="font-size: 14px; color: #666;">For security reasons, never share this OTP with anyone.</p>
          <p style="color: #999; font-size: 12px; margin-top: 30px;">If you didn't request this, please ignore this email.</p>
        </div>
      `
        });
        console.log('OTP email sent to:', email);
    } catch (error) {
        console.error('Error sending OTP email:', error);
        throw error;
    }
}

async function sendBookingConfirmation(email, bookingId) {
    try {
        await transporter.sendMail({
            from: `"RMC+ Diagnostics" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Booking Confirmed - RMC+',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1f4179;">Booking Confirmed!</h2>
          <p>Your booking (ID: <strong>#${bookingId}</strong>) has been successfully confirmed.</p>
          <p>We will notify you when your reports are ready.</p>
          <p>Thank you for choosing RMC+!</p>
        </div>
      `
        });
    } catch (error) {
        console.error('Error sending booking confirmation:', error);
    }
}

async function sendReportReadyEmail(email, bookingId) {
    try {
        await transporter.sendMail({
            from: `"RMC+ Diagnostics" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your Report is Ready - RMC+',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1f4179;">Your Report is Ready!</h2>
          <p>Your diagnostic report for booking <strong>#${bookingId}</strong> is now available.</p>
          <p>Please visit <a href="${process.env.FRONTEND_URL}/bookings">My Bookings</a> to download your report.</p>
          <p>Thank you for choosing RMC+!</p>
        </div>
      `
        });
    } catch (error) {
        console.error('Error sending report ready email:', error);
    }
}

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

async function authenticateToken(req, res, next) {
    // Check for token in cookie (for user frontend) or Authorization header (for admin panel)
    let token = req.cookies.auth_token;

    // If no cookie, check Authorization header
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7); // Remove 'Bearer ' prefix
        }
    }

    if (!token) {
        return res.status(401).json({ ok: false, message: 'Authentication required' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (error) {
        clearAuthCookie(res);
        return res.status(403).json({ ok: false, message: 'Invalid or expired token' });
    }
}

// Admin middleware
function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ ok: false, message: 'Authentication required' });
    }
    if (req.user.role !== 'admin') {
        return res.status(403).json({ ok: false, message: 'Admin access required' });
    }
    next();
}

// ============================================
// VALIDATION MIDDLEWARE
// ============================================

const validateEmail = body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email required');

const validateOTP = body('otp')
    .isLength({ min: 5, max: 5 })
    .isNumeric()
    .withMessage('OTP must be 5 digits');

const validateProfile = [
    body('name').trim().isLength({ min: 2, max: 100 }).escape(),
    body('mobile').trim().matches(/^[0-9]{10}$/),
    body('age').optional().isInt({ min: 1, max: 150 }),
    body('address').optional().trim().isLength({ max: 500 }).escape(),
    body('city').trim().isLength({ min: 2, max: 100 }).escape(),
    body('pincode').optional().trim().isLength({ max: 20 }).escape(),
    body('state').optional().trim().isLength({ max: 100 }).escape()
];

function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ ok: false, errors: errors.array() });
    }
    next();
}

// ============================================
// AUTH ROUTES
// ============================================

// Request OTP
app.post('/api/auth/request-otp',
    authLimiter,
    validateEmail,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email } = req.body;

            const otp = generateOTP();
            const hashedOTP = await hashOTP(otp);
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

            // Delete old OTPs for this email
            await pool.query('DELETE FROM otps WHERE email=?', [email]);

            await pool.query(
                'INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
                [email, hashedOTP, expiresAt]
            );

            await sendOtpMail(email, otp);

            res.json({ ok: true, message: 'OTP sent to your email' });
        } catch (error) {
            console.error('Request OTP error:', error);
            res.status(500).json({ ok: false, message: 'Failed to send OTP' });
        }
    }
);

// Verify OTP
app.post('/api/auth/verify-otp',
    authLimiter,
    [validateEmail, validateOTP],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email, otp } = req.body;

            const [otpRows] = await pool.query(
                'SELECT * FROM otps WHERE email=? AND used=0 AND expires_at>NOW() ORDER BY id DESC LIMIT 1',
                [email]
            );

            if (!otpRows.length) {
                return res.status(400).json({ ok: false, message: 'Invalid or expired OTP' });
            }

            const otpRecord = otpRows[0];
            const isValid = await verifyOTP(otp, otpRecord.otp);

            if (!isValid) {
                return res.status(400).json({ ok: false, message: 'Invalid OTP' });
            }

            // Mark OTP as used
            await pool.query('UPDATE otps SET used=1 WHERE id=?', [otpRecord.id]);

            // Check if user exists
            const [users] = await pool.query('SELECT * FROM users WHERE email=?', [email]);

            if (!users.length) {
                // New user - return temp token
                const tempToken = signJwt({ email, newUser: true });
                return res.json({ ok: true, isNewUser: true, tempToken });
            }

            // Existing user - set auth cookie
            const user = users[0];
            const token = signJwt({ id: user.id, email: user.email, role: user.role });
            setAuthCookie(res, token);

            res.json({
                ok: true,
                isNewUser: false,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    mobile: user.mobile,
                    age: user.age,
                    address: user.address,
                    city: user.city,
                    pincode: user.pincode,
                    state: user.state,
                    role: user.role,
                    selected_store_id: user.selected_store_id
                }
            });
        } catch (error) {
            console.error('Verify OTP error:', error);
            res.status(500).json({ ok: false, message: 'Verification failed' });
        }
    }
);

// ============================================
// ADMIN AUTH ROUTES
// ============================================

// Admin Request OTP (only for admins)
app.post('/api/admin/auth/request-otp',
    authLimiter,
    validateEmail,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email } = req.body;

            // Check if email exists in admins table
            const [admins] = await pool.query('SELECT * FROM admins WHERE email=?', [email]);

            if (!admins.length) {
                return res.status(403).json({ ok: false, message: 'Access denied. Admin email not found.' });
            }

            const otp = generateOTP();
            const hashedOTP = await hashOTP(otp);
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

            // Delete old OTPs for this email
            await pool.query('DELETE FROM otps WHERE email=?', [email]);

            await pool.query(
                'INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
                [email, hashedOTP, expiresAt]
            );

            await sendOtpMail(email, otp);

            res.json({ ok: true, message: 'OTP sent to your email' });
        } catch (error) {
            console.error('Admin Request OTP error:', error);
            res.status(500).json({ ok: false, message: 'Failed to send OTP' });
        }
    }
);

// Admin Verify OTP
app.post('/api/admin/auth/verify-otp',
    authLimiter,
    [validateEmail, validateOTP],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email, otp } = req.body;

            // First verify the email is an admin
            const [admins] = await pool.query('SELECT * FROM admins WHERE email=?', [email]);

            if (!admins.length) {
                return res.status(403).json({ ok: false, message: 'Access denied. Admin email not found.' });
            }

            const admin = admins[0];

            // Verify OTP
            const [otpRows] = await pool.query(
                'SELECT * FROM otps WHERE email=? AND used=0 AND expires_at>NOW() ORDER BY id DESC LIMIT 1',
                [email]
            );

            if (!otpRows.length) {
                return res.status(400).json({ ok: false, message: 'Invalid or expired OTP' });
            }

            const otpRecord = otpRows[0];
            const isValid = await verifyOTP(otp, otpRecord.otp);

            if (!isValid) {
                return res.status(400).json({ ok: false, message: 'Invalid OTP' });
            }

            // Mark OTP as used
            await pool.query('UPDATE otps SET used=1 WHERE id=?', [otpRecord.id]);

            // Create or update user record with admin role
            let [users] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
            let user;

            if (!users.length) {
                // Create user record with admin role
                const [result] = await pool.query(
                    'INSERT INTO users (email, name, role) VALUES (?, ?, ?)',
                    [email, admin.name || 'Admin', 'admin']
                );
                const [newUsers] = await pool.query('SELECT * FROM users WHERE id=?', [result.insertId]);
                user = newUsers[0];
            } else {
                // Update existing user to admin role if not already
                user = users[0];
                if (user.role !== 'admin') {
                    await pool.query('UPDATE users SET role=? WHERE id=?', ['admin', user.id]);
                    user.role = 'admin';
                }
            }

            // Set auth cookie with admin role
            const token = signJwt({ id: user.id, email: user.email, role: 'admin' });
            setAuthCookie(res, token);

            res.json({
                ok: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name || admin.name,
                    role: 'admin'
                }
            });
        } catch (error) {
            console.error('Admin Verify OTP error:', error);
            res.status(500).json({ ok: false, message: 'Verification failed' });
        }
    }
);

// Complete profile (for new users)
app.post('/api/users/profile',
    validateProfile,
    handleValidationErrors,
    async (req, res) => {
        try {
            // For new users, they send tempToken in body
            const { tempToken, name, mobile, age, address, city, pincode, state } = req.body;

            if (!tempToken) {
                return res.status(401).json({ ok: false, message: 'Token required' });
            }
            let payload;
            try {
                payload = jwt.verify(tempToken, process.env.JWT_SECRET);
            } catch (err) {
                return res.status(400).json({ ok: false, message: 'Invalid token' });
            }
            // Insert new user into DB and mark as verified
            const [result] = await pool.query(
                'INSERT INTO users (email, name, mobile, age, address, city, pincode, state, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [payload.email, name, mobile, age, address, city, pincode, state, true]
            );
            const userId = result.insertId;
            // Create JWT and set auth cookie
            const newToken = signJwt({ id: userId, email: payload.email, role: 'user' });
            setAuthCookie(res, newToken);
            // Respond with created user data
            res.json({
                ok: true,
                user: {
                    id: userId,
                    email: payload.email,
                    name,
                    mobile,
                    age,
                    address,
                    city,
                    pincode,
                    state,
                    role: 'user'
                }
            });
        } catch (error) {
            console.error('Profile creation error:', error);
            res.status(500).json({ ok: false, message: 'Failed to create profile' });
        }
    }
);

// Get current user
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query(`
            SELECT u.*, s.city as store_city, s.pincode as store_pincode
            FROM users u
            LEFT JOIN stores s ON s.id = u.selected_store_id
            WHERE u.id=?
        `, [req.user.id]);

        if (!users.length) {
            return res.status(404).json({ ok: false, message: 'User not found' });
        }

        const user = users[0];
        res.json({
            ok: true,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                mobile: user.mobile,
                age: user.age,
                address: user.address,
                city: user.city,
                pincode: user.pincode,
                state: user.state,
                role: user.role,
                selected_store_id: user.selected_store_id,
                store_city: user.store_city,
                store_pincode: user.store_pincode
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch user' });
    }
});

// Update user's selected store
app.put('/api/users/select-store', authenticateToken, async (req, res) => {
    try {
        const { store_id } = req.body;

        if (!store_id) {
            return res.status(400).json({ ok: false, message: 'Store ID required' });
        }

        // Verify store exists
        const [stores] = await pool.query('SELECT * FROM stores WHERE id=?', [store_id]);
        if (!stores.length) {
            return res.status(404).json({ ok: false, message: 'Store not found' });
        }

        // Update user's selected store
        await pool.query('UPDATE users SET selected_store_id=? WHERE id=?', [store_id, req.user.id]);

        const store = stores[0];
        res.json({
            ok: true,
            message: 'Store updated successfully',
            store: {
                id: store.id,
                city: store.city,
                pincode: store.pincode,
                address: store.address
            }
        });
    } catch (error) {
        console.error('Update store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update store' });
    }
});

// Get user's bookings
app.get('/api/users/bookings', authenticateToken, async (req, res) => {
    try {
        const [bookings] = await pool.query(`
            SELECT b.*, r.file_path as report_url
            FROM bookings b
            LEFT JOIN reports r ON b.id = r.booking_id
            WHERE b.user_id = ?
            ORDER BY b.created_at DESC
        `, [req.user.id]);

        res.json({ ok: true, bookings });
    } catch (error) {
        console.error('Get user bookings error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch bookings' });
    }
});

// Download booking report
app.get('/api/users/bookings/:id/report', authenticateToken, async (req, res) => {
    try {
        const [bookings] = await pool.query(`
            SELECT b.user_id, r.file_path
            FROM bookings b
            LEFT JOIN reports r ON b.id = r.booking_id
            WHERE b.id = ?
        `, [req.params.id]);

        if (bookings.length === 0) {
            return res.status(404).json({ ok: false, message: 'Booking not found' });
        }

        // Verify booking belongs to user
        if (bookings[0].user_id !== req.user.id) {
            return res.status(403).json({ ok: false, message: 'Access denied' });
        }

        if (!bookings[0].file_path) {
            return res.status(404).json({ ok: false, message: 'Report not available yet' });
        }

        // Return the report URL (Cloudinary URL or file path)
        res.json({ ok: true, report_url: bookings[0].file_path });
    } catch (error) {
        console.error('Download report error:', error);
        res.status(500).json({ ok: false, message: 'Failed to download report' });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ ok: true, message: 'Logged out successfully' });
});

// ============================================
// PUBLIC ROUTES (Stores, Tests, Packages)
// ============================================

// Get all stores
// Get active stores (Public)
app.get('/api/stores', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM stores WHERE is_active = true ORDER BY city');
        res.json(rows);
    } catch (error) {
        console.error('Get stores error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch stores' });
    }
});

// Get active banners (Public)
app.get('/api/banners', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM banners WHERE is_active = true ORDER BY display_order ASC');
        res.json(rows);
    } catch (error) {
        console.error('Get banners error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch banners' });
    }
});

// Get active services (Public)
app.get('/api/services', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM services WHERE is_active = true ORDER BY display_order ASC');
        res.json(rows);
    } catch (error) {
        console.error('Get services error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch services' });
    }
});

// Get active tests (Public)
app.get('/api/tests', async (req, res) => {
    try {
        const search = req.query.search || '';
        const [rows] = await pool.query(
            'SELECT * FROM tests WHERE is_active = true AND name LIKE ? ORDER BY name',
            [`%${search}%`]
        );
        res.json(rows);
    } catch (error) {
        console.error('Get tests error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch tests' });
    }
});

// Get active packages (Public)
app.get('/api/packages', async (req, res) => {
    try {
        const [packages] = await pool.query(`
      SELECT p.*, 
        (SELECT COUNT(*) FROM package_tests pt WHERE pt.package_id=p.id) as tests_count 
      FROM packages p 
      WHERE p.is_active = true
      ORDER BY p.created_at DESC
    `);
        res.json(packages);
    } catch (error) {
        console.error('Get packages error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch packages' });
    }
});

// Admin: Get all tests
app.get('/api/admin/tests', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM tests ORDER BY created_at DESC');
        res.json(rows);
    } catch (error) {
        console.error('Admin get tests error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch tests' });
    }
});

// Admin: Get all packages
app.get('/api/admin/packages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [packages] = await pool.query(`
      SELECT p.*, 
        (SELECT COUNT(*) FROM package_tests pt WHERE pt.package_id=p.id) as tests_count 
      FROM packages p 
      ORDER BY p.created_at DESC
    `);
        res.json(packages);
    } catch (error) {
        console.error('Admin get packages error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch packages' });
    }
});

// Admin: Services CRUD
app.get('/api/admin/services', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM services ORDER BY display_order ASC');
        res.json(rows);
    } catch (error) {
        console.error('Admin get services error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch services' });
    }
});

app.post('/api/admin/services', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, description, icon, is_active, display_order } = req.body;
        await pool.query(
            'INSERT INTO services (title, description, icon, is_active, display_order) VALUES (?, ?, ?, ?, ?)',
            [title, description, icon, is_active ?? true, display_order || 0]
        );
        res.json({ ok: true, message: 'Service created successfully' });
    } catch (error) {
        console.error('Create service error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create service' });
    }
});

app.put('/api/admin/services/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, description, icon, is_active, display_order } = req.body;
        await pool.query(
            'UPDATE services SET title=?, description=?, icon=?, is_active=?, display_order=? WHERE id=?',
            [title, description, icon, is_active, display_order, req.params.id]
        );
        res.json({ ok: true, message: 'Service updated successfully' });
    } catch (error) {
        console.error('Update service error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update service' });
    }
});

app.delete('/api/admin/services/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM services WHERE id=?', [req.params.id]);
        res.json({ ok: true, message: 'Service deleted successfully' });
    } catch (error) {
        console.error('Delete service error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete service' });
    }
});

// Get package details with tests
app.get('/api/packages/:id', async (req, res) => {
    try {
        const packageId = req.params.id;

        const [packages] = await pool.query('SELECT * FROM packages WHERE id=?', [packageId]);

        if (!packages.length) {
            return res.status(404).json({ ok: false, message: 'Package not found' });
        }

        const [tests] = await pool.query(`
      SELECT t.* FROM tests t
      JOIN package_tests pt ON t.id = pt.test_id
      WHERE pt.package_id = ?
    `, [packageId]);

        res.json({
            ...packages[0],
            tests
        });
    } catch (error) {
        console.error('Get package details error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch package details' });
    }
});

// ============================================
// BOOKING & PAYMENT ROUTES (Protected)
// ============================================

// Create dummy order (Bypass Razorpay for testing)
app.post('/api/bookings/create-dummy-order', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { items, delivery_option, store_id, user_details } = req.body;

        if (!items || !items.length) {
            return res.status(400).json({ ok: false, message: 'Cart is empty' });
        }

        if (!delivery_option || !['home', 'store'].includes(delivery_option)) {
            return res.status(400).json({ ok: false, message: 'Invalid delivery option' });
        }

        // Update user profile with provided details
        if (user_details) {
            await pool.query(
                'UPDATE users SET name=?, mobile=?, address=?, city=?, pincode=?, state=? WHERE id=?',
                [
                    user_details.name || null,
                    user_details.mobile || null,
                    user_details.address || null,
                    user_details.city || null,
                    user_details.pincode || null,
                    user_details.state || null,
                    userId
                ]
            );
        }

        // Get user email for booking
        const [userRows] = await pool.query('SELECT email, name, mobile FROM users WHERE id=?', [userId]);
        const userEmail = userRows[0]?.email;
        const userName = user_details?.name || userRows[0]?.name;
        const userMobile = user_details?.mobile || userRows[0]?.mobile;

        // Calculate total price
        let priceTotal = 0;

        for (const item of items) {
            if (item.type === 'test') {
                const [rows] = await pool.query('SELECT price FROM tests WHERE id=?', [item.id]);
                if (rows[0]) {
                    priceTotal += parseFloat(rows[0].price) * (item.qty || 1);
                }
            } else if (item.type === 'package') {
                const [rows] = await pool.query('SELECT price FROM packages WHERE id=?', [item.id]);
                if (rows[0]) {
                    priceTotal += parseFloat(rows[0].price) * (item.qty || 1);
                }
            }
        }

        // Get store city if store delivery
        let storeCity = null;
        if (delivery_option === 'store' && store_id) {
            const [storeRows] = await pool.query('SELECT city FROM stores WHERE id=?', [store_id]);
            storeCity = storeRows[0]?.city;
        }

        // Create booking record (Confirmed immediately)
        const [result] = await pool.query(
            'INSERT INTO bookings (user_id, user_name, email, mobile, items_json, delivery_option, store_id, store_city, status, price_total, razorpay_order_id, payment_status, patient_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                userId,
                userName,
                userEmail,
                userMobile,
                JSON.stringify(items),
                delivery_option,
                store_id || null,
                storeCity,
                'confirmed',
                priceTotal,
                'DUMMY_ORDER_' + Date.now(),
                'completed',
                JSON.stringify(user_details || {})
            ]
        );

        const bookingId = result.insertId;

        // Simulate Email Notification
        console.log(`\n📧 ========== NEW BOOKING NOTIFICATION ==========`);
        console.log(`   Booking ID: #${bookingId}`);
        console.log(`   Customer: ${userName} (${userEmail})`);
        console.log(`   Mobile: ${userMobile}`);
        console.log(`   Amount: ₹${priceTotal}`);
        console.log(`   Delivery: ${delivery_option === 'home' ? 'Home Collection' : 'Store Visit'}`);
        if (storeCity) console.log(`   Store: ${storeCity}`);
        console.log(`   Items: ${items.length} item(s)`);
        console.log(`================================================\n`);

        res.json({
            ok: true,
            bookingId,
            amount: priceTotal,
            message: 'Booking confirmed successfully'
        });
    } catch (error) {
        console.error('Create dummy order error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create order' });
    }
});

// Create order (booking + Razorpay order)
app.post('/api/bookings/create-order', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { items, delivery_option, store_id, user_details } = req.body;

        if (!items || !items.length) {
            return res.status(400).json({ ok: false, message: 'Cart is empty' });
        }

        if (!delivery_option || !['home', 'store'].includes(delivery_option)) {
            return res.status(400).json({ ok: false, message: 'Invalid delivery option' });
        }

        // Calculate total price
        let priceTotal = 0;

        for (const item of items) {
            if (item.type === 'test') {
                const [rows] = await pool.query('SELECT price FROM tests WHERE id=?', [item.id]);
                if (rows[0]) {
                    priceTotal += parseFloat(rows[0].price) * (item.qty || 1);
                }
            } else if (item.type === 'package') {
                const [rows] = await pool.query('SELECT price FROM packages WHERE id=?', [item.id]);
                if (rows[0]) {
                    priceTotal += parseFloat(rows[0].price) * (item.qty || 1);
                }
            }
        }

        const amountPaise = Math.round(priceTotal * 100);

        // Create Razorpay order
        const razorpayOrder = await razorpay.orders.create({
            amount: amountPaise,
            currency: 'INR',
            receipt: `rcpt_${Date.now()}`
        });

        // Create booking record
        const [result] = await pool.query(
            'INSERT INTO bookings (user_id, items_json, delivery_option, store_id, status, price_total, razorpay_order_id, patient_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, JSON.stringify(items), delivery_option, store_id || null, 'pending', priceTotal, razorpayOrder.id, JSON.stringify(user_details || {})]
        );

        const bookingId = result.insertId;

        res.json({
            ok: true,
            bookingId,
            razorpay_order: razorpayOrder,
            amount: priceTotal
        });
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create order' });
    }
});

// Confirm payment
app.post('/api/bookings/confirm-payment', authenticateToken, async (req, res) => {
    try {
        const { bookingId, razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

        // Verify signature
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(razorpay_order_id + '|' + razorpay_payment_id)
            .digest('hex');

        if (expectedSignature !== razorpay_signature) {
            return res.status(400).json({ ok: false, message: 'Invalid payment signature' });
        }

        // Update booking
        await pool.query(
            'UPDATE bookings SET razorpay_payment_id=?, status=? WHERE id=?',
            [razorpay_payment_id, 'pending', bookingId]
        );

        // Send confirmation email
        const [bookings] = await pool.query(`
      SELECT u.email FROM bookings b 
      JOIN users u ON u.id=b.user_id 
      WHERE b.id=?
    `, [bookingId]);

        if (bookings[0]) {
            await sendBookingConfirmation(bookings[0].email, bookingId);
        }

        res.json({ ok: true, message: 'Payment confirmed' });
    } catch (error) {
        console.error('Confirm payment error:', error);
        res.status(500).json({ ok: false, message: 'Payment confirmation failed' });
    }
});

// Get user bookings
app.get('/api/bookings/my', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const [bookings] = await pool.query(`
      SELECT b.*, s.city as store_city, s.address as store_address,
        (SELECT file_path FROM reports WHERE booking_id=b.id LIMIT 1) as report_path
      FROM bookings b
      LEFT JOIN stores s ON s.id=b.store_id
      WHERE b.user_id=?
      ORDER BY b.created_at DESC
    `, [userId]);

        res.json(bookings);
    } catch (error) {
        console.error('Get bookings error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch bookings' });
    }
});

// ============================================
// ADMIN ROUTES (Protected)
// ============================================

// Admin: Get all bookings
app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const status = req.query.status || null;

        let query = `
      SELECT b.*, u.email, u.name as user_name, u.mobile,
        s.city as store_city, s.address as store_address,
        (SELECT file_path FROM reports WHERE booking_id=b.id LIMIT 1) as report_path
      FROM bookings b
      JOIN users u ON u.id=b.user_id
      LEFT JOIN stores s ON s.id=b.store_id
    `;

        const params = [];

        if (status) {
            query += ' WHERE b.status=?';
            params.push(status);
        }

        query += ' ORDER BY b.created_at DESC';

        const [bookings] = await pool.query(query, params);
        res.json(bookings);
    } catch (error) {
        console.error('Admin get bookings error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch bookings' });
    }
});

// Admin: Upload report (SECURE)
app.post('/api/admin/bookings/:id/upload-report',
    authenticateToken,
    requireAdmin,
    upload.single('report'),
    async (req, res) => {
        try {
            const bookingId = req.params.id;

            if (!req.file) {
                return res.status(400).json({ ok: false, message: 'No file uploaded' });
            }

            const filePath = req.file.path;

            // Insert report record
            await pool.query(
                'INSERT INTO reports (booking_id, file_path, uploaded_by) VALUES (?, ?, ?)',
                [bookingId, filePath, req.user.id]
            );

            // Update booking status to completed
            await pool.query('UPDATE bookings SET status=? WHERE id=?', ['completed', bookingId]);

            // Send email notification
            const [bookings] = await pool.query(`
      SELECT u.email FROM bookings b 
      JOIN users u ON u.id=b.user_id 
      WHERE b.id=?
    `, [bookingId]);

            if (bookings[0]) {
                await sendReportReadyEmail(bookings[0].email, bookingId);
            }

            res.json({ ok: true, message: 'Report uploaded successfully', filePath });
        } catch (error) {
            console.error('Upload report error:', error);
            // Delete uploaded file if database operation fails
            if (req.file) {
                fs.unlinkSync(req.file.path);
            }
            res.status(500).json({ ok: false, message: 'Failed to upload report' });
        }
    }
);

// Admin: Get all stores
app.get('/api/admin/stores', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM stores ORDER BY city');
        res.json(rows);
    } catch (error) {
        console.error('Get admin stores error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch stores' });
    }
});

// Admin: Create store
app.post('/api/admin/stores', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { city, pincode, address, is_active } = req.body;

        if (!city || !pincode) {
            return res.status(400).json({ ok: false, message: 'City and pincode required' });
        }

        const [result] = await pool.query(
            'INSERT INTO stores (city, pincode, address, is_active) VALUES (?, ?, ?, ?)',
            [city, pincode, address, is_active !== undefined ? is_active : true]
        );

        res.json({ ok: true, id: result.insertId });
    } catch (error) {
        console.error('Create store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create store' });
    }
});

// Admin: Update store
app.put('/api/admin/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const { city, pincode, address, is_active } = req.body;

        await pool.query(
            'UPDATE stores SET city=?, pincode=?, address=?, is_active=? WHERE id=?',
            [city, pincode, address, is_active, storeId]
        );

        res.json({ ok: true, message: 'Store updated' });
    } catch (error) {
        console.error('Update store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update store' });
    }
});

// Admin: Delete store
app.delete('/api/admin/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        await pool.query('DELETE FROM stores WHERE id=?', [storeId]);
        res.json({ ok: true, message: 'Store deleted' });
    } catch (error) {
        console.error('Delete store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete store' });
    }
});

// Admin: Create test
app.post('/api/admin/tests', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, description, price, delivery_options } = req.body;

        if (!name || !price) {
            return res.status(400).json({ ok: false, message: 'Name and price required' });
        }

        const [result] = await pool.query(
            'INSERT INTO tests (name, description, price, delivery_options) VALUES (?, ?, ?, ?)',
            [name, description, price, delivery_options || 'store']
        );

        res.json({ ok: true, id: result.insertId });
    } catch (error) {
        console.error('Create test error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create test' });
    }
});

// Admin: Update test
app.put('/api/admin/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const testId = req.params.id;
        const { name, description, price, delivery_options } = req.body;

        await pool.query(
            'UPDATE tests SET name=?, description=?, price=?, delivery_options=? WHERE id=?',
            [name, description, price, delivery_options, testId]
        );

        res.json({ ok: true, message: 'Test updated' });
    } catch (error) {
        console.error('Update test error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update test' });
    }
});

// Admin: Delete test
app.delete('/api/admin/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const testId = req.params.id;
        await pool.query('DELETE FROM tests WHERE id=?', [testId]);
        res.json({ ok: true, message: 'Test deleted' });
    } catch (error) {
        console.error('Delete test error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete test' });
    }
});

// Admin: Create package
app.post('/api/admin/packages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, description, price, delivery_options, tests } = req.body;

        if (!name || !price) {
            return res.status(400).json({ ok: false, message: 'Name and price required' });
        }

        const [result] = await pool.query(
            'INSERT INTO packages (name, description, price, delivery_options) VALUES (?, ?, ?, ?)',
            [name, description, price, delivery_options || 'store']
        );

        const packageId = result.insertId;

        // Add tests to package
        if (Array.isArray(tests) && tests.length > 0) {
            for (const testId of tests) {
                await pool.query(
                    'INSERT INTO package_tests (package_id, test_id) VALUES (?, ?)',
                    [packageId, testId]
                );
            }
        }

        res.json({ ok: true, id: packageId });
    } catch (error) {
        console.error('Create package error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create package' });
    }
});

// Admin: Update package
app.put('/api/admin/packages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const packageId = req.params.id;
        const { name, description, price, delivery_options, tests } = req.body;

        await pool.query(
            'UPDATE packages SET name=?, description=?, price=?, delivery_options=? WHERE id=?',
            [name, description, price, delivery_options, packageId]
        );

        // Update package tests
        if (Array.isArray(tests)) {
            // Remove existing tests
            await pool.query('DELETE FROM package_tests WHERE package_id=?', [packageId]);

            // Add new tests
            for (const testId of tests) {
                await pool.query(
                    'INSERT INTO package_tests (package_id, test_id) VALUES (?, ?, ?)',
                    [packageId, testId]
                );
            }
        }

        res.json({ ok: true, message: 'Package updated' });
    } catch (error) {
        console.error('Update package error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update package' });
    }
});

// Admin: Delete package
app.delete('/api/admin/packages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const packageId = req.params.id;
        await pool.query('DELETE FROM packages WHERE id=?', [packageId]);
        res.json({ ok: true, message: 'Package deleted' });
    } catch (error) {
        console.error('Delete package error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete package' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ ok: true, message: 'RMC+ API is running securely' });
});

// ============================================
// ADMIN STORE MANAGEMENT ROUTES
// ============================================

// Admin: Create store
app.post('/api/admin/stores', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, city, pincode, address, phone } = req.body;

        if (!name || !city || !pincode || !address) {
            return res.status(400).json({ ok: false, message: 'Name, city, pincode, and address are required' });
        }

        const [result] = await pool.query(
            'INSERT INTO stores (name, city, pincode, address, phone) VALUES (?, ?, ?, ?, ?)',
            [name, city, pincode, address, phone]
        );

        res.json({ ok: true, id: result.insertId, message: 'Store created successfully' });
    } catch (error) {
        console.error('Create store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create store' });
    }
});

// Admin: Update store
app.put('/api/admin/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const { name, city, pincode, address, phone } = req.body;

        await pool.query(
            'UPDATE stores SET name=?, city=?, pincode=?, address=?, phone=? WHERE id=?',
            [name, city, pincode, address, phone, storeId]
        );

        res.json({ ok: true, message: 'Store updated successfully' });
    } catch (error) {
        console.error('Update store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update store' });
    }
});

// Admin: Delete store
app.delete('/api/admin/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;

        // Check if any users are associated with this store
        const [users] = await pool.query('SELECT COUNT(*) as count FROM users WHERE selected_store_id = ?', [storeId]);
        if (users[0].count > 0) {
            return res.status(400).json({
                ok: false,
                message: `Cannot delete store. ${users[0].count} user(s) are associated with this store.`
            });
        }

        await pool.query('DELETE FROM stores WHERE id=?', [storeId]);
        res.json({ ok: true, message: 'Store deleted successfully' });
    } catch (error) {
        console.error('Delete store error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete store' });
    }
});

// ============================================
// BANNER MANAGEMENT ROUTES
// ============================================

// Public: Get active banners for hero section
app.get('/api/banners', async (req, res) => {
    try {
        const [banners] = await pool.query(
            'SELECT * FROM banners WHERE is_active = TRUE ORDER BY display_order ASC, created_at DESC'
        );
        res.json(banners);
    } catch (error) {
        console.error('Get banners error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch banners' });
    }
});

// Admin: Get all banners (including inactive)
app.get('/api/admin/banners', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [banners] = await pool.query('SELECT * FROM banners ORDER BY display_order ASC, created_at DESC');
        res.json({ ok: true, banners });
    } catch (error) {
        console.error('Get all banners error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch banners' });
    }
});

// Admin: Upload file (generic)
app.post('/api/admin/upload',
    authenticateToken,
    requireAdmin,
    upload.single('file'),
    (req, res) => {
        if (!req.file) {
            return res.status(400).json({ ok: false, message: 'No file uploaded' });
        }
        // Return relative path for frontend use
        const relativePath = req.file.path.replace(/\\/g, '/');
        res.json({ ok: true, filePath: relativePath });
    }
);

// Admin: Create banner
app.post('/api/admin/banners', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, subtitle, cta_text, cta_link, image_url, background_color, is_active, display_order } = req.body;

        if (!title) {
            return res.status(400).json({ ok: false, message: 'Title is required' });
        }

        const [result] = await pool.query(
            `INSERT INTO banners (title, subtitle, cta_text, cta_link, image_url, background_color, is_active, display_order) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [title, subtitle, cta_text, cta_link, image_url, background_color || '#667eea', is_active ?? true, display_order || 0]
        );

        res.json({ ok: true, id: result.insertId, message: 'Banner created successfully' });
    } catch (error) {
        console.error('Create banner error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create banner' });
    }
});

// Admin: Update banner
app.put('/api/admin/banners/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bannerId = req.params.id;
        const { title, subtitle, cta_text, cta_link, image_url, background_color, is_active, display_order } = req.body;

        await pool.query(
            `UPDATE banners SET title=?, subtitle=?, cta_text=?, cta_link=?, image_url=?, background_color=?, is_active=?, display_order=? 
             WHERE id=?`,
            [title, subtitle, cta_text, cta_link, image_url, background_color, is_active, display_order, bannerId]
        );

        res.json({ ok: true, message: 'Banner updated successfully' });
    } catch (error) {
        console.error('Update banner error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update banner' });
    }
});

// Admin: Delete banner
app.delete('/api/admin/banners/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bannerId = req.params.id;
        await pool.query('DELETE FROM banners WHERE id=?', [bannerId]);
        res.json({ ok: true, message: 'Banner deleted successfully' });
    } catch (error) {
        console.error('Delete banner error:', error);
        res.status(500).json({ ok: false, message: 'Failed to delete banner' });
    }
});

// ============================================
// ADMIN ORDER MANAGEMENT
// ============================================

// Admin: Get all bookings with filters
app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, payment_status } = req.query;

        let query = `
            SELECT b.*, u.name as user_name, u.email, u.mobile 
            FROM bookings b 
            LEFT JOIN users u ON b.user_id = u.id 
            WHERE 1=1
        `;
        const params = [];

        if (status) {
            query += ' AND b.status = ?';
            params.push(status);
        }

        if (payment_status) {
            query += ' AND b.payment_status = ?';
            params.push(payment_status);
        }

        query += ' ORDER BY b.created_at DESC';

        const [bookings] = await pool.query(query, params);
        res.json({ ok: true, bookings });
    } catch (error) {
        console.error('Get bookings error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch bookings' });
    }
});

// Admin: Update booking status
app.put('/api/admin/bookings/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookingId = req.params.id;
        const { status } = req.body;

        if (!['pending', 'processing', 'completed'].includes(status)) {
            return res.status(400).json({ ok: false, message: 'Invalid status' });
        }

        await pool.query('UPDATE bookings SET status=? WHERE id=?', [status, bookingId]);
        res.json({ ok: true, message: 'Booking status updated' });
    } catch (error) {
        console.error('Update booking status error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update booking status' });
    }
});

// Admin: Upload report for booking
app.put('/api/admin/bookings/:id/report', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookingId = req.params.id;
        const { report_path } = req.body;

        if (!report_path) {
            return res.status(400).json({ ok: false, message: 'Report path is required' });
        }

        await pool.query(
            'UPDATE bookings SET report_path=?, status=? WHERE id=?',
            [report_path, 'completed', bookingId]
        );

        // Get booking details for email
        const [bookings] = await pool.query('SELECT * FROM bookings WHERE id=?', [bookingId]);
        if (bookings.length > 0) {
            const booking = bookings[0];
            // Send report ready email
            await sendReportReadyEmail(booking.email, bookingId);
        }

        res.json({ ok: true, message: 'Report uploaded successfully' });
    } catch (error) {
        console.error('Upload report error:', error);
        res.status(500).json({ ok: false, message: 'Failed to upload report' });
    }
});

// Admin: Get dashboard statistics
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Get today's date range
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);

        // New orders today
        const [newOrders] = await pool.query(
            'SELECT COUNT(*) as count FROM bookings WHERE created_at >= ? AND created_at < ?',
            [today, tomorrow]
        );

        // Pending actions
        const [pendingActions] = await pool.query(
            'SELECT COUNT(*) as count FROM bookings WHERE status = ? OR (status = ? AND report_path IS NULL)',
            ['pending', 'processing']
        );

        // Total patients
        const [totalPatients] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['user']);

        // Monthly revenue
        const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        const [monthlyRevenue] = await pool.query(
            'SELECT SUM(price_total) as total FROM bookings WHERE payment_status = ? AND created_at >= ?',
            ['completed', firstDayOfMonth]
        );

        res.json({
            ok: true,
            stats: {
                newOrders: newOrders[0].count,
                pendingActions: pendingActions[0].count,
                totalPatients: totalPatients[0].count,
                monthlyRevenue: monthlyRevenue[0].total || 0
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch statistics' });
    }
});

// ============================================
// ADMIN USER MANAGEMENT (Super Admin Only)
// ============================================

// Check if user is super admin
const requireSuperAdmin = async (req, res, next) => {
    try {
        // Get super admin email from environment or use default
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'southindian100107@gmail.com';

        if (req.user.email !== superAdminEmail) {
            return res.status(403).json({ ok: false, message: 'Access denied. Super admin only.' });
        }

        next();
    } catch (error) {
        res.status(500).json({ ok: false, message: 'Authorization error' });
    }
};

// Get all admin users
app.get('/api/admin/users/admins', authenticateToken, requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const [admins] = await pool.query(
            'SELECT id, email, name, role, is_verified, created_at FROM users WHERE role = ? ORDER BY created_at DESC',
            ['admin']
        );
        res.json({ ok: true, admins });
    } catch (error) {
        console.error('Get admins error:', error);
        res.status(500).json({ ok: false, message: 'Failed to fetch admin users' });
    }
});

// Create new admin user
app.post('/api/admin/users/admins', authenticateToken, requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { email, name } = req.body;

        if (!email || !name) {
            return res.status(400).json({ ok: false, message: 'Email and name are required' });
        }

        // Check if user already exists
        const [existing] = await pool.query('SELECT id, role FROM users WHERE email = ?', [email]);

        if (existing.length > 0) {
            // User exists, update to admin role
            await pool.query(
                'UPDATE users SET role = ?, name = ?, is_verified = ? WHERE email = ?',
                ['admin', name, true, email]
            );
            res.json({ ok: true, message: 'User updated to admin role', userId: existing[0].id });
        } else {
            // Create new admin user
            const [result] = await pool.query(
                'INSERT INTO users (email, name, role, is_verified) VALUES (?, ?, ?, ?)',
                [email, name, 'admin', true]
            );
            res.json({ ok: true, message: 'Admin user created successfully', userId: result.insertId });
        }
    } catch (error) {
        console.error('Create admin error:', error);
        res.status(500).json({ ok: false, message: 'Failed to create admin user' });
    }
});

// Update admin user
app.put('/api/admin/users/admins/:id', authenticateToken, requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const { name, email } = req.body;

        // Prevent modifying super admin
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'southindian100107@gmail.com';
        const [user] = await pool.query('SELECT email FROM users WHERE id = ?', [userId]);

        if (user.length > 0 && user[0].email === superAdminEmail) {
            return res.status(403).json({ ok: false, message: 'Cannot modify super admin user' });
        }

        await pool.query(
            'UPDATE users SET name = ?, email = ? WHERE id = ? AND role = ?',
            [name, email, userId, 'admin']
        );

        res.json({ ok: true, message: 'Admin user updated successfully' });
    } catch (error) {
        console.error('Update admin error:', error);
        res.status(500).json({ ok: false, message: 'Failed to update admin user' });
    }
});

// Delete admin user
app.delete('/api/admin/users/admins/:id', authenticateToken, requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const userId = req.params.id;

        // Prevent deleting super admin
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'southindian100107@gmail.com';
        const [user] = await pool.query('SELECT email FROM users WHERE id = ?', [userId]);

        if (user.length > 0 && user[0].email === superAdminEmail) {
            return res.status(403).json({ ok: false, message: 'Cannot delete super admin user' });
        }

        // Change role to user instead of deleting
        await pool.query(
            'UPDATE users SET role = ? WHERE id = ? AND role = ?',
            ['user', userId, 'admin']
        );

        res.json({ ok: true, message: 'Admin privileges removed successfully' });
    } catch (error) {
        console.error('Delete admin error:', error);
        res.status(500).json({ ok: false, message: 'Failed to remove admin user' });
    }
});

// Check if current user is super admin
app.get('/api/admin/users/is-super-admin', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'southindian100107@gmail.com';
        const isSuperAdmin = req.user.email === superAdminEmail;
        res.json({ ok: true, isSuperAdmin, superAdminEmail });
    } catch (error) {
        console.error('Check super admin error:', error);
        res.status(500).json({ ok: false, message: 'Failed to check super admin status' });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ ok: false, message: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ ok: false, message: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 5000;

initializeDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`\n${'='.repeat(50)}`);
        console.log(`🚀 RMC+ Secure Backend running on port ${PORT}`);
        console.log(`${'='.repeat(50)}`);
        console.log(`📧 Email configured: ${process.env.EMAIL_USER}`);
        console.log(`💳 Razorpay configured: ${process.env.RAZORPAY_KEY_ID ? 'Yes' : 'No'}`);
        console.log(`🔒 Security features enabled:`);
        console.log(`   ✓ HttpOnly Cookies`);
        console.log(`   ✓ Hashed OTPs (bcrypt)`);
        console.log(`   ✓ Rate Limiting`);
        console.log(`   ✓ Helmet Security Headers`);
        console.log(`   ✓ Input Validation`);
        console.log(`   ✓ Secure File Uploads`);
        console.log(`   ✓ CORS Protection`);
        console.log(`${'='.repeat(50)}\n`);
    });
}).catch(err => {
    console.error('❌ Failed to initialize database:', err);
    process.exit(1);
});
