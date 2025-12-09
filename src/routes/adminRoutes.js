const express = require('express');
const router = express.Router();
const { uploadBanner, uploadServiceImage, uploadReport } = require('../config/upload'); // Use local upload config
const fs = require('fs');
const path = require('path');

// Helper to delete local file
const deleteLocalFile = (filePath) => {
    if (!filePath) return;
    try {
        // file_path stored as '/uploads/filename.ext', we need relative system path
        // filePath starts with /, so remove it
        const relativePath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
        const absolutePath = path.resolve(__dirname, '../../', relativePath);

        if (fs.existsSync(absolutePath)) {
            fs.unlinkSync(absolutePath);
            console.log(`Deleted file: ${absolutePath}`);
        }
    } catch (err) {
        console.error(`Failed to delete file ${filePath}:`, err);
    }
};

// Middleware to check if user is admin
const requireAdmin = (req, res, next) => {
    if (!req.user || !req.user.is_admin) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Middleware to check if user is super admin
const requireSuperAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'super_admin') {
        return res.status(403).json({ message: 'Super admin access required' });
    }
    next();
};

module.exports = (pool, sendOtpMail, authenticateToken) => {

    // ============================================
    // ADMIN AUTHENTICATION
    // ============================================

    // Send OTP to admin
    router.post('/auth/send-otp', async (req, res) => {
        try {
            const { email } = req.body;

            // Check if email is an admin
            const [admins] = await pool.query(
                'SELECT * FROM admins WHERE email = ? AND is_active = TRUE',
                [email]
            );

            if (admins.length === 0) {
                return res.status(403).json({ message: 'Not authorized' });
            }

            // Generate and send OTP
            const otp = Math.floor(10000 + Math.random() * 90000).toString();
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

            await pool.query(
                'INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
                [email, otp, expiresAt]
            );

            // Send email
            console.log(`[DEV] OTP for ${email}: ${otp}`); // Always log in dev

            if (sendOtpMail) {
                try {
                    await sendOtpMail(email, otp);
                } catch (emailError) {
                    console.error('Failed to send OTP email:', emailError);
                }
            } else {
                console.warn('sendOtpMail function not provided to adminRoutes');
            }

            res.json({ message: 'OTP sent successfully' });
        } catch (error) {
            console.error('Admin send OTP error:', error);
            res.status(500).json({ message: 'Failed to send OTP' });
        }
    });

    // Verify OTP and login
    router.post('/auth/verify-otp', async (req, res) => {
        try {
            const { email, otp } = req.body;

            const [otpRows] = await pool.query(
                'SELECT * FROM otps WHERE email = ? AND otp = ? AND used = FALSE AND expires_at > NOW() ORDER BY id DESC LIMIT 1',
                [email, otp]
            );

            if (otpRows.length === 0) {
                return res.status(400).json({ message: 'Invalid or expired OTP' });
            }

            // Mark OTP as used
            await pool.query('UPDATE otps SET used = TRUE WHERE id = ?', [otpRows[0].id]);

            // Get admin details
            const [admins] = await pool.query(
                'SELECT id, email, name, role, is_active FROM admins WHERE email = ? AND is_active = TRUE',
                [email]
            );

            if (admins.length === 0) {
                return res.status(403).json({ message: 'Admin not found or inactive' });
            }

            const admin = admins[0];

            // Generate JWT token
            const jwt = require('jsonwebtoken');
            const token = jwt.sign(
                { id: admin.id, email: admin.email, role: admin.role, is_admin: true },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '7d' }
            );

            res.json({ token, admin });
        } catch (error) {
            console.error('Admin verify OTP error:', error);
            res.status(500).json({ message: 'Failed to verify OTP' });
        }
    });

    // Get current admin info
    router.get('/auth/me', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [admins] = await pool.query(
                'SELECT id, email, name, role, is_active FROM admins WHERE id = ?',
                [req.user.id]
            );

            if (admins.length === 0) {
                return res.status(404).json({ message: 'Admin not found' });
            }

            res.json({ admin: admins[0] });
        } catch (error) {
            console.error('Get admin info error:', error);
            res.status(500).json({ message: 'Failed to get admin info' });
        }
    });

    // ============================================
    // BANNERS MANAGEMENT
    // ============================================

    // Get all banners
    router.get('/banners', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [banners] = await pool.query(
                'SELECT * FROM banners ORDER BY display_order ASC, created_at DESC'
            );
            res.json({ banners });
        } catch (error) {
            console.error('Get banners error:', error);
            res.status(500).json({ message: 'Failed to get banners' });
        }
    });

    // Create banner
    router.post('/banners', authenticateToken, requireAdmin, uploadBanner.single('image'), async (req, res) => {
        try {
            const { title, subtitle, badge, description, custom_html, cta_text, cta_link, background_color, layout_type, is_active, display_order } = req.body;
            console.log('Received banner data:', { title, layout_type, custom_html_length: custom_html ? custom_html.length : 0 });

            // Store relative path: /uploads/filename.ext
            const image_url = req.file ? `/uploads/${req.file.filename}` : null;

            const [result] = await pool.query(
                'INSERT INTO banners (title, subtitle, badge, description, custom_html, cta_text, cta_link, image_url, background_color, layout_type, is_active, display_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [title, subtitle, badge, description, custom_html || null, cta_text, cta_link, image_url, background_color, layout_type || 'default', is_active === 'true' || is_active === true, display_order || 0]
            );

            res.json({ message: 'Banner created successfully', id: result.insertId });
        } catch (error) {
            console.error('Create banner error DETAILS:', error);
            res.status(500).json({ message: 'Failed to create banner', error: error.message, stack: error.stack });
        }
    });

    // Update banner
    router.put('/banners/:id', authenticateToken, requireAdmin, uploadBanner.single('image'), async (req, res) => {
        try {
            const { id } = req.params;
            const { title, subtitle, badge, description, custom_html, cta_text, cta_link, background_color, layout_type, is_active, display_order } = req.body;

            let updateQuery = 'UPDATE banners SET title = ?, subtitle = ?, badge = ?, description = ?, custom_html = ?, cta_text = ?, cta_link = ?, background_color = ?, layout_type = ?, is_active = ?, display_order = ?';
            let params = [title, subtitle, badge, description, custom_html, cta_text, cta_link, background_color, layout_type || 'default', is_active, display_order];

            if (req.file) {
                // Format path for local storage URL
                updateQuery += ', image_url = ?';
                params.push(`/uploads/${req.file.filename}`);
            }

            updateQuery += ' WHERE id = ?';
            params.push(id);

            await pool.query(updateQuery, params);

            res.json({ message: 'Banner updated successfully' });
        } catch (error) {
            console.error('Update banner error:', error);
            res.status(500).json({ message: 'Failed to update banner' });
        }
    });


    // Debug fix schema
    router.get('/debug-fix-schema', async (req, res) => {
        try {
            // Check if column exists first
            const [columns] = await pool.query("SHOW COLUMNS FROM banners LIKE 'custom_html'");
            if (columns.length === 0) {
                await pool.query('ALTER TABLE banners ADD COLUMN custom_html LONGTEXT');
                res.json({ message: 'Column added successfully' });
            } else {
                res.json({ message: 'Column already exists' });
            }
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Update banner status
    router.patch('/banners/:id/status', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { is_active } = req.body;

            await pool.query('UPDATE banners SET is_active = ? WHERE id = ?', [is_active, id]);

            res.json({ message: 'Banner status updated successfully' });
        } catch (error) {
            console.error('Update banner status error:', error);
            res.status(500).json({ message: 'Failed to update banner status' });
        }
    });

    // Delete banner
    router.delete('/banners/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;

            // Get banner to delete image from local storage
            const [banners] = await pool.query('SELECT image_url FROM banners WHERE id = ?', [id]);

            if (banners.length > 0 && banners[0].image_url) {
                // Delete local file
                deleteLocalFile(banners[0].image_url);
            }

            await pool.query('DELETE FROM banners WHERE id = ?', [id]);

            res.json({ message: 'Banner deleted successfully' });
        } catch (error) {
            console.error('Delete banner error:', error);
            res.status(500).json({ message: 'Failed to delete banner' });
        }
    });

    // ============================================
    // TESTS MANAGEMENT
    // ============================================

    // Get all tests
    router.get('/tests', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [tests] = await pool.query('SELECT * FROM tests ORDER BY created_at DESC');
            res.json({ tests });
        } catch (error) {
            console.error('Get tests error:', error);
            res.status(500).json({ message: 'Failed to get tests' });
        }
    });

    // Create test
    router.post('/tests', authenticateToken, requireAdmin, uploadServiceImage.single('image'), async (req, res) => {
        try {
            const { name, description, price, delivery_options, is_available } = req.body;
            // Store relative path: /uploads/filename.ext
            const image_url = req.file ? `/uploads/${req.file.filename}` : null;

            const [result] = await pool.query(
                'INSERT INTO tests (name, description, price, delivery_options, image_url, is_available) VALUES (?, ?, ?, ?, ?, ?)',
                [name, description, price, delivery_options, image_url, is_available]
            );

            res.json({ message: 'Test created successfully', id: result.insertId });
        } catch (error) {
            console.error('Create test error:', error);
            res.status(500).json({ message: 'Failed to create test' });
        }
    });

    // Update test
    router.put('/tests/:id', authenticateToken, requireAdmin, uploadServiceImage.single('image'), async (req, res) => {
        try {
            const { id } = req.params;
            const { name, description, price, delivery_options, is_available } = req.body;

            let updateQuery = 'UPDATE tests SET name = ?, description = ?, price = ?, delivery_options = ?, is_available = ?';
            let params = [name, description, price, delivery_options, is_available];

            if (req.file) {
                updateQuery += ', image_url = ?';
                params.push(`/uploads/${req.file.filename}`);
            }

            updateQuery += ' WHERE id = ?';
            params.push(id);

            await pool.query(updateQuery, params);

            res.json({ message: 'Test updated successfully' });
        } catch (error) {
            console.error('Update test error:', error);
            res.status(500).json({ message: 'Failed to update test' });
        }
    });

    // Delete test
    router.delete('/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;

            // Get test to delete image from local storage
            const [tests] = await pool.query('SELECT image_url FROM tests WHERE id = ?', [id]);

            if (tests.length > 0 && tests[0].image_url) {
                deleteLocalFile(tests[0].image_url);
            }

            await pool.query('DELETE FROM tests WHERE id = ?', [id]);
            res.json({ message: 'Test deleted successfully' });
        } catch (error) {
            console.error('Delete test error:', error);
            res.status(500).json({ message: 'Failed to delete test' });
        }
    });

    // Toggle test availability
    router.patch('/tests/:id/availability', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { is_available } = req.body;

            await pool.query('UPDATE tests SET is_available = ? WHERE id = ?', [is_available, id]);

            res.json({ message: 'Test availability updated successfully' });
        } catch (error) {
            console.error('Update test availability error:', error);
            res.status(500).json({ message: 'Failed to update test availability' });
        }
    });

    // ============================================
    // BOOKINGS MANAGEMENT
    // ============================================

    // Get dashboard statistics (for dashboard page)
    router.get('/dashboard/stats', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [stats] = await pool.query(`
                SELECT 
                    SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as totalOrdersToday,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pendingReports,
                    SUM(CASE WHEN delivery_option = 'home' AND status = 'pending' THEN 1 ELSE 0 END) as homeCollectionActive,
                    SUM(CASE WHEN delivery_option = 'store' AND status = 'pending' THEN 1 ELSE 0 END) as storeAppointmentsActive,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completedOrders,
                    (SELECT COUNT(*) FROM banners WHERE is_active = TRUE) as activeBanners
                FROM bookings
            `);

            res.json(stats[0]);
        } catch (error) {
            console.error('Get dashboard stats error:', error);
            res.status(500).json({ message: 'Failed to get statistics' });
        }
    });

    // Get dashboard statistics
    router.get('/bookings/stats', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [stats] = await pool.query(`
        SELECT 
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pendingOrders,
          SUM(CASE WHEN status = 'order_taken' THEN 1 ELSE 0 END) as ordersTaken,
          SUM(CASE WHEN status = 'waiting_for_scan' THEN 1 ELSE 0 END) as waitingForScan,
          SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completedOrders,
          SUM(CASE WHEN status = 'completed' THEN price_total ELSE 0 END) as totalRevenue,
          SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as todayOrders
        FROM bookings
      `);

            res.json(stats[0]);
        } catch (error) {
            console.error('Get stats error:', error);
            res.status(500).json({ message: 'Failed to get statistics' });
        }
    });

    // Get all bookings with filters
    router.get('/bookings', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { status, delivery_mode, limit = 100 } = req.query;

            let query = `
                SELECT b.*, 
                       COALESCE(u.name, b.user_name) as user_name, 
                       COALESCE(u.email, b.email) as user_email, 
                       COALESCE(u.mobile, b.mobile) as user_mobile, 
                       u.address as user_address,
                       r.file_path as report_url,
                       CASE 
                           WHEN b.type = 'package' THEN p.name
                           WHEN b.type = 'test' THEN t.name
                           ELSE 'N/A'
                       END as item_name,
                       s.id as store_id,
                       s.name as store_name,
                       s.city as store_city,
                       s.address as store_address
                FROM bookings b
                LEFT JOIN users u ON b.user_id = u.id
                LEFT JOIN reports r ON b.id = r.booking_id
                LEFT JOIN packages p ON b.type = 'package' AND b.item_id = p.id
                LEFT JOIN tests t ON b.type = 'test' AND b.item_id = t.id
                LEFT JOIN stores s ON b.store_id = s.id
            `;

            const params = [];
            const conditions = [];

            if (status && status !== 'all') {
                conditions.push('b.status = ?');
                params.push(status);
            }

            if (delivery_mode && delivery_mode !== 'all') {
                const dbDeliveryOption = delivery_mode === 'home_collection' ? 'home' :
                    delivery_mode === 'store_visit' ? 'store' : delivery_mode;
                conditions.push('b.delivery_option = ?');
                params.push(dbDeliveryOption);
            }

            if (req.query.store_id && req.query.store_id !== 'all') {
                conditions.push('b.store_id = ?');
                params.push(req.query.store_id);
            }

            if (conditions.length > 0) {
                query += ' WHERE ' + conditions.join(' AND ');
            }

            query += ' ORDER BY b.created_at DESC LIMIT ?';
            params.push(parseInt(limit));

            const [bookings] = await pool.query(query, params);

            res.json({ bookings });
        } catch (error) {
            console.error('Get bookings error:', error);
            res.status(500).json({ message: 'Failed to get bookings' });
        }
    });

    // Get booking details
    router.get('/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;

            const [bookings] = await pool.query(`
        SELECT b.*, 
                COALESCE(u.name, b.user_name) as user_name, 
                COALESCE(u.email, b.email) as user_email, 
                COALESCE(u.mobile, b.mobile) as user_mobile,
                u.address as user_address, u.city as user_city, u.pincode as user_pincode,
                r.file_path as report_url,
                CASE 
                    WHEN b.type = 'package' THEN p.name
                    WHEN b.type = 'test' THEN t.name
                    ELSE 'N/A'
                END as item_name
        FROM bookings b
        LEFT JOIN users u ON b.user_id = u.id
        LEFT JOIN reports r ON b.id = r.booking_id
        LEFT JOIN packages p ON b.type = 'package' AND b.item_id = p.id
        LEFT JOIN tests t ON b.type = 'test' AND b.item_id = t.id
        WHERE b.id = ?
                `, [id]);

            if (bookings.length === 0) {
                return res.status(404).json({ message: 'Booking not found' });
            }

            res.json(bookings[0]);
        } catch (error) {
            console.error('Get booking details error:', error);
            res.status(500).json({ message: 'Failed to get booking details' });
        }
    });

    // ============================================
    // PHLEBOTOMISTS MANAGEMENT
    // ============================================

    // Search phlebotomists
    router.get('/phlebotomists', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { search } = req.query;
            let query = 'SELECT * FROM phlebotomists WHERE is_active = TRUE';
            const params = [];

            if (search) {
                query += ' AND (name LIKE ? OR mobile LIKE ?)';
                params.push(`%${search}%`, `%${search}%`);
            }

            query += ' ORDER BY name ASC LIMIT 10';

            const [result] = await pool.query(query, params);
            res.json({ phlebotomists: result });
        } catch (error) {
            console.error('Search phlebotomists error:', error);
            res.status(500).json({ message: 'Failed to search phlebotomists' });
        }
    });

    // Create phlebotomist
    router.post('/phlebotomists', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { name, mobile } = req.body;
            await pool.query('INSERT INTO phlebotomists (name, mobile) VALUES (?, ?)', [name, mobile]);
            res.json({ message: 'Phlebotomist added successfully' });
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Mobile number already exists' });
            }
            console.error('Create phlebotomist error:', error);
            res.status(500).json({ message: 'Failed to create phlebotomist' });
        }
    });

    // Update Phlebotomist details (Home Collection)
    router.patch('/bookings/:id/phlebotomist', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { phlebotomist_name, arrival_time, phlebotomist_mobile } = req.body;

            // Ensure column exists (quick fix for schema evolution)
            try {
                await pool.query("ALTER TABLE bookings ADD COLUMN phlebotomist_mobile VARCHAR(20)");
            } catch (e) { /* ignore if exists */ }

            await pool.query(
                'UPDATE bookings SET phlebotomist_name = ?, phlebotomist_arrival_time = ?, phlebotomist_mobile = ? WHERE id = ?',
                [phlebotomist_name, arrival_time, phlebotomist_mobile, id]
            );

            res.json({ message: 'Phlebotomist details updated successfully' });
        } catch (error) {
            console.error('Update phlebotomist details error:', error);
            res.status(500).json({ message: 'Failed to update phlebotomist details' });
        }
    });

    // Update booking status
    router.patch('/bookings/:id/status', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { status } = req.body;

            const validStatuses = ['pending', 'order_taken', 'waiting_for_scan', 'processing', 'report_generating', 'completed', 'cancelled'];

            if (!validStatuses.includes(status)) {
                return res.status(400).json({ message: 'Invalid status' });
            }

            await pool.query('UPDATE bookings SET status = ? WHERE id = ?', [status, id]);

            res.json({ message: 'Booking status updated successfully' });
        } catch (error) {
            console.error('Update booking status error:', error);
            res.status(500).json({ message: 'Failed to update booking status' });
        }
    });

    // Upload report
    router.post('/bookings/:id/report', authenticateToken, requireAdmin, uploadReport.single('report'), async (req, res) => {
        try {
            const { id } = req.params;

            if (!req.file) {
                return res.status(400).json({ message: 'No file uploaded' });
            }

            // For local storage, using the filename generated by multer
            const file_path = `/uploads/${req.file.filename}`;

            // Check if report already exists
            const [existing] = await pool.query('SELECT * FROM reports WHERE booking_id = ?', [id]);

            if (existing.length > 0) {
                // Delete old file if exists
                if (existing[0].file_path) {
                    deleteLocalFile(existing[0].file_path);
                }

                await pool.query(
                    'UPDATE reports SET file_path = ?, uploaded_by = ? WHERE booking_id = ?',
                    [file_path, req.user.id, id]
                );
            } else {
                // Insert report
                await pool.query(
                    'INSERT INTO reports (booking_id, file_path, uploaded_by) VALUES (?, ?, ?)',
                    [id, file_path, req.user.id]
                );
            }

            // Update booking status to completed
            await pool.query('UPDATE bookings SET status = ? WHERE id = ?', ['completed', id]);

            res.json({ message: 'Report uploaded successfully' });
        } catch (error) {
            console.error('Upload report error:', error);
            res.status(500).json({ message: 'Failed to upload report' });
        }
    });

    // ============================================
    // USERS MANAGEMENT
    // ============================================

    // Get all users
    router.get('/users', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [users] = await pool.query('SELECT id, email, name, mobile, city, created_at FROM users ORDER BY created_at DESC');
            res.json({ users });
        } catch (error) {
            console.error('Get users error:', error);
            res.status(500).json({ message: 'Failed to get users' });
        }
    });

    // Get user details
    router.get('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);

            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            res.json(users[0]);
        } catch (error) {
            console.error('Get user details error:', error);
            res.status(500).json({ message: 'Failed to get user details' });
        }
    });

    // ============================================
    // ADMINS MANAGEMENT (Super Admin Only)
    // ============================================

    // Get all admins
    router.get('/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
        try {
            const [admins] = await pool.query('SELECT id, email, name, role, is_active, created_at FROM admins ORDER BY created_at DESC');
            res.json({ admins });
        } catch (error) {
            console.error('Get admins error:', error);
            res.status(500).json({ message: 'Failed to get admins' });
        }
    });

    // Create admin
    router.post('/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
        try {
            const { email, name, role } = req.body;

            const [result] = await pool.query(
                'INSERT INTO admins (email, name, role) VALUES (?, ?, ?)',
                [email, name, role || 'admin']
            );

            res.json({ message: 'Admin created successfully', id: result.insertId });
        } catch (error) {
            console.error('Create admin error:', error);
            res.status(500).json({ message: 'Failed to create admin' });
        }
    });

    // Update admin
    router.put('/admins/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { name, role, is_active } = req.body;

            await pool.query(
                'UPDATE admins SET name = ?, role = ?, is_active = ? WHERE id = ?',
                [name, role, is_active, id]
            );

            res.json({ message: 'Admin updated successfully' });
        } catch (error) {
            console.error('Update admin error:', error);
            res.status(500).json({ message: 'Failed to update admin' });
        }
    });

    // Delete admin
    router.delete('/admins/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
        try {
            const { id } = req.params;

            // Prevent deleting yourself
            if (parseInt(id) === req.user.id) {
                return res.status(400).json({ message: 'Cannot delete yourself' });
            }

            await pool.query('DELETE FROM admins WHERE id = ?', [id]);

            res.json({ message: 'Admin deleted successfully' });
        } catch (error) {
            console.error('Delete admin error:', error);
            res.status(500).json({ message: 'Failed to delete admin' });
        }
    });

    // ============================================
    // TESTS CRUD
    // ============================================

    // Get all tests
    router.get('/tests', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [tests] = await pool.query('SELECT * FROM tests ORDER BY created_at DESC');
            res.json(tests);
        } catch (error) {
            console.error('Get tests error:', error);
            res.status(500).json({ message: 'Failed to fetch tests' });
        }
    });

    // Create test
    router.post('/tests', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { name, description, price, duration, category, preparation_instructions, is_active } = req.body;

            await pool.query(
                'INSERT INTO tests (name, description, price, duration, category, preparation_instructions, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [name, description, price, duration, category, preparation_instructions, is_active ?? true]
            );

            res.json({ message: 'Test created successfully' });
        } catch (error) {
            console.error('Create test error:', error);
            res.status(500).json({ message: 'Failed to create test' });
        }
    });

    // Update test
    router.put('/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { name, description, price, duration, category, preparation_instructions, is_active } = req.body;

            await pool.query(
                'UPDATE tests SET name=?, description=?, price=?, duration=?, category=?, preparation_instructions=?, is_active=? WHERE id=?',
                [name, description, price, duration, category, preparation_instructions, is_active, id]
            );

            res.json({ message: 'Test updated successfully' });
        } catch (error) {
            console.error('Update test error:', error);
            res.status(500).json({ message: 'Failed to update test' });
        }
    });

    // Toggle test status
    router.patch('/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { is_active } = req.body;

            await pool.query('UPDATE tests SET is_active=? WHERE id=?', [is_active, id]);

            res.json({ message: 'Test status updated successfully' });
        } catch (error) {
            console.error('Toggle test error:', error);
            res.status(500).json({ message: 'Failed to update test status' });
        }
    });

    // Delete test
    router.delete('/tests/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            await pool.query('DELETE FROM tests WHERE id=?', [id]);
            res.json({ message: 'Test deleted successfully' });
        } catch (error) {
            console.error('Delete test error:', error);
            res.status(500).json({ message: 'Failed to delete test' });
        }
    });

    // ============================================
    // PACKAGES CRUD
    // ============================================

    // Get all packages
    router.get('/packages', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [packages] = await pool.query('SELECT * FROM packages ORDER BY created_at DESC');

            // Get tests for each package
            for (let pkg of packages) {
                const [tests] = await pool.query(`
                    SELECT t.* FROM tests t
                    INNER JOIN package_tests pt ON t.id = pt.test_id
                    WHERE pt.package_id = ?
                `, [pkg.id]);
                pkg.tests = tests;
            }

            res.json(packages);
        } catch (error) {
            console.error('Get packages error:', error);
            res.status(500).json({ message: 'Failed to fetch packages' });
        }
    });

    // Create package
    router.post('/packages', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { name, description, price, discount_percentage, is_active, test_ids } = req.body;

            const [result] = await pool.query(
                'INSERT INTO packages (name, description, price, discount_percentage, is_active) VALUES (?, ?, ?, ?, ?)',
                [name, description, price, discount_percentage || 0, is_active ?? true]
            );

            const packageId = result.insertId;

            // Add tests to package
            if (test_ids && test_ids.length > 0) {
                for (let testId of test_ids) {
                    await pool.query(
                        'INSERT INTO package_tests (package_id, test_id) VALUES (?, ?)',
                        [packageId, testId]
                    );
                }
            }

            res.json({ message: 'Package created successfully' });
        } catch (error) {
            console.error('Create package error:', error);
            res.status(500).json({ message: 'Failed to create package' });
        }
    });

    // Update package
    router.put('/packages/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { name, description, price, discount_percentage, is_active, test_ids } = req.body;

            await pool.query(
                'UPDATE packages SET name=?, description=?, price=?, discount_percentage=?, is_active=? WHERE id=?',
                [name, description, price, discount_percentage || 0, is_active, id]
            );

            // Update package tests
            if (test_ids !== undefined) {
                await pool.query('DELETE FROM package_tests WHERE package_id=?', [id]);

                if (test_ids.length > 0) {
                    for (let testId of test_ids) {
                        await pool.query(
                            'INSERT INTO package_tests (package_id, test_id) VALUES (?, ?)',
                            [id, testId]
                        );
                    }
                }
            }

            res.json({ message: 'Package updated successfully' });
        } catch (error) {
            console.error('Update package error:', error);
            res.status(500).json({ message: 'Failed to update package' });
        }
    });

    // Delete package
    router.delete('/packages/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            await pool.query('DELETE FROM packages WHERE id=?', [id]);
            res.json({ message: 'Package deleted successfully' });
        } catch (error) {
            console.error('Delete package error:', error);
            res.status(500).json({ message: 'Failed to delete package' });
        }
    });

    // ============================================
    // STORES CRUD
    // ============================================

    // Get all stores
    router.get('/stores', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [stores] = await pool.query('SELECT * FROM stores ORDER BY created_at DESC');
            res.json(stores);
        } catch (error) {
            console.error('Get stores error:', error);
            res.status(500).json({ message: 'Failed to fetch stores' });
        }
    });

    // Create store
    router.post('/stores', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { name, address, city, pincode, phone, email, opening_time, closing_time, is_active } = req.body;

            await pool.query(
                'INSERT INTO stores (name, address, city, pincode, phone, email, opening_time, closing_time, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [name, address, city, pincode, phone, email, opening_time, closing_time, is_active ?? true]
            );

            res.json({ message: 'Store created successfully' });
        } catch (error) {
            console.error('Create store error:', error);
            res.status(500).json({ message: 'Failed to create store' });
        }
    });

    // Update store
    router.put('/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { name, address, city, pincode, phone, email, opening_time, closing_time, is_active } = req.body;

            await pool.query(
                'UPDATE stores SET name=?, address=?, city=?, pincode=?, phone=?, email=?, opening_time=?, closing_time=?, is_active=? WHERE id=?',
                [name, address, city, pincode, phone, email, opening_time, closing_time, is_active, id]
            );

            res.json({ message: 'Store updated successfully' });
        } catch (error) {
            console.error('Update store error:', error);
            res.status(500).json({ message: 'Failed to update store' });
        }
    });

    // Toggle store status
    router.patch('/stores/:id/status', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            const { is_active } = req.body;

            await pool.query('UPDATE stores SET is_active=? WHERE id=?', [is_active, id]);

            res.json({ message: 'Store status updated successfully' });
        } catch (error) {
            console.error('Update store status error:', error);
            res.status(500).json({ message: 'Failed to update store status' });
        }
    });

    // Delete store
    router.delete('/stores/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            await pool.query('DELETE FROM stores WHERE id=?', [id]);
            res.json({ message: 'Store deleted successfully' });
        } catch (error) {
            console.error('Delete store error:', error);
            res.status(500).json({ message: 'Failed to delete store' });
        }
    });

    // ============================================
    // BANNERS CRUD
    // ============================================

    // Get all banners
    router.get('/banners', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const [banners] = await pool.query('SELECT * FROM banners ORDER BY display_order ASC');
            res.json(banners);
        } catch (error) {
            console.error('Get banners error:', error);
            res.status(500).json({ message: 'Failed to fetch banners' });
        }
    });

    // Create banner
    router.post('/banners', authenticateToken, requireAdmin, uploadBanner.single('image'), async (req, res) => {
        try {
            const { title, subtitle, cta_text, cta_link, background_color, display_order, is_active } = req.body;
            let image_url = req.body.image_url;

            if (req.file) {
                image_url = req.file.path;
            }

            await pool.query(
                'INSERT INTO banners (title, subtitle, image_url, cta_text, cta_link, background_color, display_order, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [title, subtitle, image_url, cta_text, cta_link, background_color, display_order || 0, is_active === 'true' || is_active === true]
            );

            res.json({ message: 'Banner created successfully' });
        } catch (error) {
            console.error('Create banner error:', error);
            res.status(500).json({ message: 'Failed to create banner' });
        }
    });

    // Update banner
    router.put('/banners/:id', authenticateToken, requireAdmin, uploadBanner.single('image'), async (req, res) => {
        try {
            const { id } = req.params;
            const { title, subtitle, cta_text, cta_link, background_color, display_order, is_active } = req.body;
            let image_url = req.body.image_url;

            if (req.file) {
                image_url = req.file.path;
            }

            // If image_url is not provided (and no new file), keep existing image
            // But here we are updating, so if image_url is undefined, we might overwrite with NULL if we are not careful.
            // However, the query updates all fields.
            // If the user doesn't upload a file, and doesn't send image_url, we should probably fetch existing or handle it in frontend.
            // The frontend should send the existing image_url if no new file is selected.

            await pool.query(
                'UPDATE banners SET title=?, subtitle=?, image_url=?, cta_text=?, cta_link=?, background_color=?, display_order=?, is_active=? WHERE id=?',
                [title, subtitle, image_url, cta_text, cta_link, background_color, display_order, is_active === 'true' || is_active === true, id]
            );

            res.json({ message: 'Banner updated successfully' });
        } catch (error) {
            console.error('Update banner error:', error);
            res.status(500).json({ message: 'Failed to update banner' });
        }
    });

    // Delete banner
    router.delete('/banners/:id', authenticateToken, requireAdmin, async (req, res) => {
        try {
            const { id } = req.params;
            await pool.query('DELETE FROM banners WHERE id=?', [id]);
            res.json({ message: 'Banner deleted successfully' });
        } catch (error) {
            console.error('Delete banner error:', error);
            res.status(500).json({ message: 'Failed to delete banner' });
        }
    });

    return router;
};
