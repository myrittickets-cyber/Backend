const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

const sendEmail = async (to, subject, html) => {
    try {
        const data = await resend.emails.send({
            from: 'RMC+ Diagnostics <onboarding@resend.dev>', // Use verified domain or default test domain
            to: [to],
            subject: subject,
            html: html,
        });
        console.log('Email sent successfully:', data);
        return data;
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
};

module.exports = { sendEmail };
