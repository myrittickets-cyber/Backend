// sendEmail utility that uses Resend service
const { sendEmail: resendSend } = require('../services/emailService');

/**
 * Send an email.
 * @param {string} to - Recipient email.
 * @param {string} subject - Email subject.
 * @param {string} content - Plain text or HTML content.
 */
const sendEmail = async (to, subject, content) => {
    try {
        // Resend expects HTML; wrap plain text if needed
        const html = content.includes('<') ? content : `<p>${content}</p>`;
        await resendSend(to, subject, html);
    } catch (error) {
        console.error('Error sending email via Resend:', error);
        throw error;
    }
};

module.exports = sendEmail;
