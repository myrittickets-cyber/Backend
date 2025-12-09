const db = require('../config/db');

exports.updateProfile = async (req, res) => {
    const { name, mobile, age, address, city, pincode, state } = req.body;
    const userId = req.user.id;

    try {
        await db.query(
            'UPDATE users SET name = ?, mobile = ?, age = ?, address = ?, city = ?, pincode = ?, state = ?, is_verified = TRUE WHERE id = ?',
            [name, mobile, age, address, city, pincode, state, userId]
        );

        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        res.json({ ok: true, user: users[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
};

exports.getMe = async (req, res) => {
    try {
        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
        if (!users[0]) return res.status(404).json({ ok: false, message: 'User not found' });
        res.json(users[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
};
