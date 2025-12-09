const mysql = require('mysql2');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');

dotenv.config();

// Enhanced configuration for Railway MySQL proxy
const isProduction = process.env.NODE_ENV === 'production';
const isRailway = process.env.DB_HOST && (process.env.DB_HOST.includes('railway') || process.env.DB_HOST.includes('rlwy'));

const poolConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: isRailway ? 3 : 10,
  queueLimit: 0,
  connectTimeout: isRailway ? 20000 : 10000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  ssl: process.env.DB_SSL_CA ? {
    ca: fs.readFileSync(path.resolve(__dirname, '../../', process.env.DB_SSL_CA))
  } : undefined
};

const pool = mysql.createPool(poolConfig);

// Test connection on startup
if (isProduction || isRailway) {
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('❌ Database connection failed:', err.message);
      console.error('   Please check your Railway database credentials.');
    } else {
      console.log('✅ Database connection pool initialized successfully');
      connection.release();
    }
  });
}

module.exports = pool.promise();
