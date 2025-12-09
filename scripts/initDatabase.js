const mysql = require('mysql2/promise');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

async function initializeDatabase() {
  let connection;

  try {
    // Connect to MySQL server (without database)
    console.log('🔌 Connecting to MySQL server...');
    const sslConfig = process.env.DB_SSL_CA ? {
      ca: fs.readFileSync(path.resolve(__dirname, '../', process.env.DB_SSL_CA))
    } : undefined;

    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || process.env.DB_PASS || 'sanjay',
      port: process.env.DB_PORT || 3306,
      ssl: sslConfig
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

    // 1. Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        mobile VARCHAR(20),
        age INT,
        address TEXT,
        city VARCHAR(100),
        pincode VARCHAR(20),
        state VARCHAR(100),
        role ENUM('user', 'admin') DEFAULT 'user',
        selected_store_id INT,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_role (role)
      )
    `);
    console.log('  ✓ users table');

    // 2. OTPs table
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

    // 3. Admins table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        role ENUM('super_admin', 'admin') DEFAULT 'admin',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      )
    `);
    console.log('  ✓ admins table');

    // 4. Stores table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) DEFAULT 'Store',
        city VARCHAR(100) NOT NULL,
        pincode VARCHAR(20) NOT NULL,
        address TEXT,
        phone VARCHAR(20),
        email VARCHAR(255),
        opening_time VARCHAR(20) DEFAULT '08:00',
        closing_time VARCHAR(20) DEFAULT '20:00',
        is_active BOOLEAN DEFAULT TRUE,
        is_available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  ✓ stores table');

    // 5. Banners table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS banners (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        subtitle TEXT,
        badge VARCHAR(255),
        description TEXT,
        cta_text VARCHAR(100),
        cta_link VARCHAR(255),
        image_url VARCHAR(500),
        background_color VARCHAR(20) DEFAULT '#667eea',
        layout_type VARCHAR(50) DEFAULT 'default',
        custom_html LONGTEXT,
        is_active BOOLEAN DEFAULT TRUE,
        display_order INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    console.log('  ✓ banners table');

    // 6. Tests table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS tests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        delivery_options ENUM('home', 'store', 'both') DEFAULT 'both',
        image_url VARCHAR(500),
        is_active BOOLEAN DEFAULT TRUE,
        is_available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  ✓ tests table');

    // 7. Packages table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        delivery_options ENUM('home', 'store', 'both') DEFAULT 'both',
        category VARCHAR(100),
        image_url VARCHAR(500),
        is_active BOOLEAN DEFAULT TRUE,
        is_available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  ✓ packages table');

    // 8. Package Tests table
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

    // 9. Bookings table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type ENUM('package', 'test') NOT NULL DEFAULT 'package',
        item_id INT NOT NULL DEFAULT 0,
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
        status VARCHAR(50) DEFAULT 'pending',
        report_path VARCHAR(500),
        booking_date DATE,
        booking_time TIME,
        patient_details JSON,
        phlebotomist_name VARCHAR(255),
        phlebotomist_arrival_time VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user (user_id),
        INDEX idx_status (status)
      )
    `);
    console.log('  ✓ bookings table');

    // 10. Reports table
    await connection.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                booking_id INT NOT NULL,
                file_path VARCHAR(500),
                uploaded_by INT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
            )
        `);
    console.log('  ✓ reports table');

    // 11. Phlebotomists (NEW)
    await connection.query(`
            CREATE TABLE IF NOT EXISTS phlebotomists (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                mobile VARCHAR(20) NOT NULL UNIQUE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
    console.log('  ✓ phlebotomists table');

    // 12. Services (NEW)
    await connection.query(`
            CREATE TABLE IF NOT EXISTS services (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                icon VARCHAR(100),
                icon_url VARCHAR(500),
                is_active BOOLEAN DEFAULT TRUE,
                display_order INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
    console.log('  ✓ services table');

    // Create sample stores if none exist
    const [storeCount] = await connection.query('SELECT COUNT(*) as count FROM stores');
    if (storeCount[0].count === 0) {
      await connection.query(`INSERT INTO stores (city, pincode, address, phone) VALUES
('Pammal', '600075', 'No.47, Ground Floor, Plot No.9, 10, 11, Muthamizh Nagar, Pammal Main Road, Pammal, Chennai – 600075.', '8925995441'),
('Thiruverkadu', '600077', 'No: 1, Sivan Koil Main Road, Thambusamy Nagar, Thiruverkadu, Chennai - 600077.', '8925995443'),
('Pattabiram', '600072', 'No. 763, Dandurai Village, C.T.C. Road, Pattabiram, Chennai – 600072.', '8925995442'),
('Oragadam', '600075', 'No.47, Ground Floor, Plot No.9, 10, 11, Muthamizh Nagar, Pammal Main Road, Pammal, Chennai – 600075.', '8925995440')
            `);
      console.log('✅ Sample stores created');
    }

    // Create default super admin if none exist
    const [adminCount] = await connection.query('SELECT COUNT(*) as count FROM admins');
    if (adminCount[0].count === 0) {
      await connection.query(`INSERT INTO admins (email, name, role, is_active) VALUES
('southindian100107@gmail.com', 'Super Admin', 'super_admin', true)
            `);
      console.log('✅ Default super admin created');
    } else {
      // Ensure super admin has correct role
      await connection.query(`UPDATE admins SET role='super_admin', is_active=true WHERE email='southindian100107@gmail.com'`);
    }

    console.log('\n✅ All tables verified successfully (optimized schema)!');

  } catch (error) {
    console.error('\n❌ Error initializing database:', error);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Allow running directly or importing
if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('✅ Initialization complete');
      process.exit(0);
    })
    .catch((error) => {
      console.error('❌ Initialization failed:', error);
      process.exit(1);
    });
} else {
  module.exports = initializeDatabase;
}
