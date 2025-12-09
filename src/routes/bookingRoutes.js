const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');

module.exports = (pool) => {

    // Get My Bookings
    router.get('/my-bookings', async (req, res) => {
        try {
            const userId = req.user.id; // From authenticateToken middleware
            const [bookings] = await pool.query(
                `SELECT b.*, r.file_path as report_path 
                 FROM bookings b 
                 LEFT JOIN reports r ON b.id = r.booking_id 
                 WHERE b.user_id = ? 
                 ORDER BY b.created_at DESC`,
                [userId]
            );
            res.json(bookings);
        } catch (error) {
            console.error('Fetch my bookings error:', error);
            res.status(500).json({ ok: false, message: 'Failed to fetch bookings' });
        }
    });

    // Create dummy order (for testing/demo)
    router.post('/create-dummy-order', async (req, res) => {
        try {
            const { items, delivery_option, store_id, user_details, booking_date, booking_time } = req.body;
            const userId = req.user ? req.user.id : null;

            // Basic validation
            if (!items || items.length === 0) {
                return res.status(400).json({ ok: false, message: 'No items in order' });
            }

            // Calculate total
            const priceTotal = items.reduce((sum, item) => sum + (parseFloat(item.price) * (item.qty || 1)), 0);

            // Get store city if store_id provided
            let storeCity = null;
            if (store_id) {
                const [stores] = await pool.query('SELECT city FROM stores WHERE id = ?', [store_id]);
                if (stores.length > 0) {
                    storeCity = stores[0].city;
                }
            }

            if (!userId) {
                return res.status(401).json({ ok: false, message: 'User not authenticated' });
            }

            const [result] = await pool.query(
                `INSERT INTO bookings 
                (user_id, user_name, email, mobile, items_json, delivery_option, store_id, store_city, 
                booking_date, booking_time, status, price_total, payment_status, patient_details) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId,
                    `${user_details.firstName} ${user_details.lastName}`,
                    req.user.email,
                    user_details.mobile,
                    JSON.stringify(items),
                    delivery_option,
                    store_id || null,
                    storeCity,
                    booking_date,
                    booking_time,
                    'pending',
                    priceTotal,
                    'pending',
                    JSON.stringify(user_details)
                ]
            );

            const bookingId = result.insertId;

            console.log(`\n📧 ========== NEW BOOKING NOTIFICATION ==========`);
            console.log(`   Booking ID: #${bookingId}`);
            console.log(`   Customer: ${user_details.firstName} ${user_details.lastName}`);
            console.log(`   Date: ${booking_date} Time: ${booking_time}`);
            console.log(`   Amount: ₹${priceTotal}`);
            console.log(`================================================\n`);

            res.json({ ok: true, bookingId, message: 'Booking created successfully' });

        } catch (error) {
            console.error('Create booking error:', error);
            res.status(500).json({ ok: false, message: 'Failed to create booking' });
        }
    });

    return router;
};
