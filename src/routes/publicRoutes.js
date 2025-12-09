const express = require('express');
const router = express.Router();

module.exports = (pool) => {

    // ============================================
    // PUBLIC BANNERS
    // ============================================

    // Get active banners
    router.get('/banners', async (req, res) => {
        try {
            const [banners] = await pool.query(
                'SELECT * FROM banners WHERE is_active = TRUE ORDER BY display_order ASC, created_at DESC'
            );
            res.json({ banners });
        } catch (error) {
            console.error('Get banners error:', error);
            res.status(500).json({ message: 'Failed to get banners' });
        }
    });

    // ============================================
    // PUBLIC SERVICES
    // ============================================

    // Get active services
    router.get('/services', async (req, res) => {
        try {
            const [services] = await pool.query(
                'SELECT * FROM services WHERE is_active = TRUE ORDER BY display_order ASC, created_at DESC'
            );
            res.json({ services });
        } catch (error) {
            console.error('Get services error:', error);
            res.status(500).json({ message: 'Failed to get services' });
        }
    });

    // ============================================
    // PUBLIC TESTS
    // ============================================

    // Get available tests with preview limit
    router.get('/tests', async (req, res) => {
        try {
            const { limit, preview } = req.query;

            let query = 'SELECT * FROM tests WHERE is_available = TRUE ORDER BY created_at DESC';

            if (preview === 'true' || limit) {
                query += ` LIMIT ${limit || 8}`;
            }

            const [tests] = await pool.query(query);
            res.json({ tests });
        } catch (error) {
            console.error('Get tests error:', error);
            res.status(500).json({ message: 'Failed to get tests' });
        }
    });

    // Get test by ID
    router.get('/tests/:id', async (req, res) => {
        try {
            const { id } = req.params;
            const [tests] = await pool.query(
                'SELECT * FROM tests WHERE id = ? AND is_available = TRUE',
                [id]
            );

            if (tests.length === 0) {
                return res.status(404).json({ message: 'Test not found' });
            }

            res.json(tests[0]);
        } catch (error) {
            console.error('Get test error:', error);
            res.status(500).json({ message: 'Failed to get test' });
        }
    });

    // ============================================
    // PUBLIC PACKAGES
    // ============================================

    // Get available packages with preview limit
    router.get('/packages', async (req, res) => {
        try {
            const { limit, preview } = req.query;

            let query = `
        SELECT p.*, 
        GROUP_CONCAT(t.name SEPARATOR ', ') as test_names,
        COUNT(pt.test_id) as test_count
        FROM packages p
        LEFT JOIN package_tests pt ON p.id = pt.package_id
        LEFT JOIN tests t ON pt.test_id = t.id
        WHERE p.is_available = TRUE
        GROUP BY p.id
        ORDER BY p.created_at DESC
      `;

            if (preview === 'true' || limit) {
                query += ` LIMIT ${limit || 6}`;
            }

            const [packages] = await pool.query(query);
            res.json({ packages });
        } catch (error) {
            console.error('Get packages error:', error);
            res.status(500).json({ message: 'Failed to get packages' });
        }
    });

    // Get package by ID with tests
    router.get('/packages/:id', async (req, res) => {
        try {
            const { id } = req.params;

            const [packages] = await pool.query(
                'SELECT * FROM packages WHERE id = ? AND is_available = TRUE',
                [id]
            );

            if (packages.length === 0) {
                return res.status(404).json({ message: 'Package not found' });
            }

            const [tests] = await pool.query(`
        SELECT t.* FROM tests t
        INNER JOIN package_tests pt ON t.id = pt.test_id
        WHERE pt.package_id = ?
      `, [id]);

            res.json({ ...packages[0], tests });
        } catch (error) {
            console.error('Get package error:', error);
            res.status(500).json({ message: 'Failed to get package' });
        }
    });

    // ============================================
    // PUBLIC STORES
    // ============================================

    // Get available stores
    router.get('/stores', async (req, res) => {
        try {
            const { city } = req.query;

            let query = 'SELECT * FROM stores WHERE is_available = TRUE';
            const params = [];

            if (city) {
                query += ' AND city = ?';
                params.push(city);
            }

            query += ' ORDER BY city, name';

            const [stores] = await pool.query(query, params);
            res.json({ stores });
        } catch (error) {
            console.error('Get stores error:', error);
            res.status(500).json({ message: 'Failed to get stores' });
        }
    });

    // Get store cities
    router.get('/stores/cities', async (req, res) => {
        try {
            const [cities] = await pool.query(
                'SELECT DISTINCT city FROM stores WHERE is_available = TRUE ORDER BY city'
            );
            res.json({ cities: cities.map(c => c.city) });
        } catch (error) {
            console.error('Get cities error:', error);
            res.status(500).json({ message: 'Failed to get cities' });
        }
    });

    return router;
};
