const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../../.env') });

async function migrate() {
    let connection;
    try {
        console.log('Connecting to database...');
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT || 3306
        });

        console.log('Connected.');

        // Add custom_html column
        try {
            await connection.query(`ALTER TABLE banners ADD COLUMN custom_html LONGTEXT DEFAULT NULL`);
            console.log('Added custom_html column to banners table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('custom_html column already exists');
            } else {
                throw error;
            }
        }

        console.log('Migration completed successfully');
    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        if (connection) await connection.end();
    }
}

migrate();
