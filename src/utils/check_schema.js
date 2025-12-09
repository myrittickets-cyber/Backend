const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'rmc_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

async function checkSchema() {
    try {
        const connection = await mysql.createConnection(dbConfig);
        console.log('Connected to database.');

        const [columns] = await connection.query('DESCRIBE banners');
        console.log('Banners table schema:');
        columns.forEach(col => {
            console.log(`${col.Field}: ${col.Type} (Null: ${col.Null}, Key: ${col.Key}, Default: ${col.Default})`);
        });

        await connection.end();
    } catch (error) {
        console.error('Error checking schema:', error);
    }
}

checkSchema();
