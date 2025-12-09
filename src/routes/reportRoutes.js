const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

module.exports = (pool) => {
    // Download report
    router.get('/download/:bookingId', async (req, res) => {
        try {
            const { bookingId } = req.params;

            // Get report details from database
            const [reports] = await pool.query(
                'SELECT file_path FROM reports WHERE booking_id = ? ORDER BY uploaded_at DESC LIMIT 1',
                [bookingId]
            );

            if (reports.length === 0) {
                return res.status(404).json({ message: 'Report not found' });
            }

            const report = reports[0];
            const filePath = report.file_path;

            // If it's a URL (Cloudinary), redirect to it
            if (filePath.startsWith('http')) {
                return res.redirect(filePath);
            }

            // If it's a local file (fallback)
            // Ensure path is correct relative to server root
            // filePath stored as '/uploads/filename.pdf'
            const relativePath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
            const absolutePath = path.resolve(__dirname, '../../', relativePath);

            if (!fs.existsSync(absolutePath)) {
                console.error('File not found at:', absolutePath);
                return res.status(404).json({ message: 'File not found on server' });
            }

            res.download(absolutePath);
        } catch (error) {
            console.error('Download report error:', error);
            res.status(500).json({ message: 'Failed to download report' });
        }
    });

    return router;
};
