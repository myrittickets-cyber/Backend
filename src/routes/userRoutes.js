const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const auth = require('../middleware/authMiddleware');

router.post('/', auth, userController.updateProfile);
router.get('/me', auth, userController.getMe);

module.exports = router;
