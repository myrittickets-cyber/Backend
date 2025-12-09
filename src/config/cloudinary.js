const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dvatkduf0',
    api_key: process.env.CLOUDINARY_API_KEY || '826268689346784',
    api_secret: process.env.CLOUDINARY_API_SECRET || 'o5EV4ldFNTBiLIJyO7J0j8T9gnU'
});

// Storage for banners
const bannerStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'rmc-banners',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        transformation: [{ width: 1920, height: 600, crop: 'limit' }]
    }
});

// Storage for test/package images
const serviceImageStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'rmc-services',
        allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
        transformation: [{ width: 800, height: 600, crop: 'limit' }]
    }
});

// Storage for reports (PDFs)
const reportStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'rmc-reports',
        allowed_formats: ['pdf', 'jpg', 'jpeg', 'png'],
        resource_type: 'auto'
    }
});

// Multer instances
const uploadBanner = multer({ storage: bannerStorage });
const uploadServiceImage = multer({ storage: serviceImageStorage });
const uploadReport = multer({ storage: reportStorage });

module.exports = {
    cloudinary,
    uploadBanner,
    uploadServiceImage,
    uploadReport
};
