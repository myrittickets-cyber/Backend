const mysql = require('mysql2/promise');
require('dotenv').config();

async function initializeDatabase() {
    let connection;

    try {
        // Connect to MySQL server (without database)
        console.log('🔌 Connecting to MySQL server...');
        connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASS || 'sanjay'
        });

        console.log('✅ Connected to MySQL server');

        // Create database
        console.log('\n📦 Creating database...');
        await connection.query(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME || 'rmc_plus'}`);
        console.log(`✅ Database '${process.env.DB_NAME || 'rmc_plus'}' created/verified`);

        // Use the database
        await connection.query(`USE ${process.env.DB_NAME || 'rmc_plus'}`);

        // Create tables
        console.log('\n📋 Creating tables...');

        // Users table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        mobile VARCHAR(20),
        age INT,
        address TEXT,
        city VARCHAR(100),
        pincode VARCHAR(10),
        state VARCHAR(100),
        role ENUM('user', 'admin') DEFAULT 'user',
        selected_store_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_role (role)
      )
    `);
        console.log('  ✓ users table');

        // OTPs table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS otps (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_expires (expires_at)
      )
    `);
        console.log('  ✓ otps table');

        // Stores table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id INT AUTO_INCREMENT PRIMARY KEY,
        city VARCHAR(100) NOT NULL,
        pincode VARCHAR(10) NOT NULL,
        address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        console.log('  ✓ stores table');

        // Tests table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS tests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        delivery_options ENUM('home', 'store', 'both') DEFAULT 'both',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        console.log('  ✓ tests table');

        // Packages table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        delivery_options ENUM('home', 'store', 'both') DEFAULT 'both',
        category VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        console.log('  ✓ packages table');

        // Package Tests table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS package_tests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT NOT NULL,
        test_id INT NOT NULL,
        FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE,
        FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE,
        UNIQUE KEY unique_package_test (package_id, test_id)
      )
    `);
        console.log('  ✓ package_tests table');

        // Bookings table
        await connection.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        user_name VARCHAR(255),
        email VARCHAR(255),
        mobile VARCHAR(20),
        store_id INT,
        store_city VARCHAR(100),
        delivery_option ENUM('home', 'store') NOT NULL,
        items_json TEXT NOT NULL,
        price_total DECIMAL(10, 2) NOT NULL,
        razorpay_order_id VARCHAR(255),
        razorpay_payment_id VARCHAR(255),
        payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        status ENUM('pending', 'processing', 'completed') DEFAULT 'pending',
        report_path VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user (user_id),
        INDEX idx_status (status),
        INDEX idx_payment_status (payment_status)
      )
    `);
        console.log('  ✓ bookings table');

        // Add foreign key for selected_store_id (if not exists)
        try {
            await connection.query(`
        ALTER TABLE users ADD CONSTRAINT fk_users_store 
        FOREIGN KEY (selected_store_id) REFERENCES stores(id) ON DELETE SET NULL
      `);
            console.log('  ✓ Added foreign key constraint');
        } catch (error) {
            if (error.code !== 'ER_DUP_KEYNAME') {
                console.log('  ⚠️  Foreign key already exists');
            }
        }

        console.log('\n✅ All tables created successfully!');

        // Create sample store
        console.log('\n📍 Creating sample store...');
        const [existingStores] = await connection.query('SELECT COUNT(*) as count FROM stores');

        if (existingStores[0].count === 0) {
            await connection.query(`
        INSERT INTO stores (city, pincode, address) VALUES
        ('Chennai', '600001', '123 Main Street, T Nagar'),
        ('Coimbatore', '641001', '456 RS Puram'),
        ('Madurai', '625001', '789 Anna Nagar')
      `);
            console.log('  ✓ Sample stores created');
        } else {
            console.log('  ⚠️  Stores already exist');
        }

        console.log('\n' + '='.repeat(50));
        console.log('🎉 DATABASE INITIALIZATION COMPLETE!');
        console.log('='.repeat(50));
        console.log('\n📝 Next steps:');
        console.log('1. Run: node scripts/populateData.js');
        console.log('2. Start backend: npm run dev');
        console.log('3. Start frontend: cd ../frontend && npm run dev\n');

    } catch (error) {
        console.error('\n❌ Error initializing database:', error);
        throw error;
    } finally {
        if (connection) {
            await connection.end();
            console.log('Database connection closed');
        }
    }
}

// Run the script
initializeDatabase()
    .then(() => {
        console.log('✅ Script completed successfully');
        process.exit(0);
    })
    .catch((error) => {
        console.error('❌ Script failed:', error);
        process.exit(1);
    });
