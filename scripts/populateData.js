const mysql = require('mysql2/promise');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

async function populateTestData() {
    console.log('🌱 Populating RMC+ with sample data...\n');

    let connection;

    try {
        const sslConfig = process.env.DB_SSL_CA ? {
            ca: fs.readFileSync(path.resolve(__dirname, '../', process.env.DB_SSL_CA))
        } : undefined;

        connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || process.env.DB_PASS || 'sanjay',
            database: process.env.DB_NAME || 'rmc_plus',
            port: process.env.DB_PORT || 3306,
            ssl: sslConfig
        });

        console.log('✅ Connected to database\n');

        // Helper to check if table is empty
        const isTableEmpty = async (table) => {
            const [rows] = await connection.query(`SELECT COUNT(*) as count FROM ${table}`);
            return rows[0].count === 0;
        };

        // 1. Tests
        if (await isTableEmpty('tests')) {
            console.log('📋 Tests table is empty. Inserting sample tests...');
            const tests = [
                { name: 'Complete Blood Count (CBC)', description: 'Comprehensive blood analysis including RBC, WBC, platelets', price: 500, delivery: 'both', is_active: true },
                { name: 'Lipid Profile', description: 'Cholesterol and triglycerides test', price: 800, delivery: 'both', is_active: true },
                { name: 'Thyroid Function Test (TFT)', description: 'T3, T4, TSH levels', price: 600, delivery: 'both', is_active: true },
                { name: 'Blood Sugar (Fasting)', description: 'Fasting glucose test', price: 200, delivery: 'both', is_active: true },
                { name: 'Liver Function Test (LFT)', description: 'Complete liver health check', price: 900, delivery: 'both', is_active: true },
                { name: 'Kidney Function Test (KFT)', description: 'Creatinine, urea, uric acid', price: 850, delivery: 'both', is_active: true }
            ];

            for (const test of tests) {
                await connection.query(
                    'INSERT INTO tests (name, description, price, delivery_options, is_active) VALUES (?, ?, ?, ?, ?)',
                    [test.name, test.description, test.price, test.delivery, test.is_active]
                );
                process.stdout.write(`   + Added: ${test.name}\n`);
            }
        } else {
            console.log('📋 Tests table already has data. Skipping insertion.');
        }

        // 2. Packages
        if (await isTableEmpty('packages')) {
            console.log('\n📦 Packages table is empty. Inserting sample packages...');
            const packages = [
                { name: 'Full Body Checkup', desc: 'Comprehensive health screening with 25+ tests', price: 2500, delivery: 'both', cat: 'Comprehensive', active: true },
                { name: 'Diabetes Care Package', desc: 'Complete diabetes monitoring package', price: 1500, delivery: 'both', cat: 'Specialized', active: true },
                { name: 'Heart Health Package', desc: 'Cardiac risk assessment package', price: 2000, delivery: 'both', cat: 'Specialized', active: true },
                { name: 'Senior Citizen Package', desc: 'Specially designed for 60+ age group', price: 3000, delivery: 'both', cat: 'Comprehensive', active: true }
            ];

            for (const pkg of packages) {
                await connection.query(
                    'INSERT INTO packages (name, description, price, delivery_options, category, is_active) VALUES (?, ?, ?, ?, ?, ?)',
                    [pkg.name, pkg.desc, pkg.price, pkg.delivery, pkg.cat, pkg.active]
                );
                process.stdout.write(`   + Added: ${pkg.name}\n`);
            }
        } else {
            console.log('\n📦 Packages table already has data. Skipping insertion.');
        }

        // 3. Package Tests (Linking)
        // Only run if we have packages and tests, and links are empty
        if (await isTableEmpty('package_tests') && !(await isTableEmpty('packages')) && !(await isTableEmpty('tests'))) {
            console.log('\n🔗 Linking tests to packages...');
            const [pkgRows] = await connection.query('SELECT id FROM packages LIMIT 1');
            const [testRows] = await connection.query('SELECT id FROM tests LIMIT 3');

            if (pkgRows.length > 0 && testRows.length > 0) {
                for (const test of testRows) {
                    await connection.query(
                        'INSERT INTO package_tests (package_id, test_id) VALUES (?, ?)',
                        [pkgRows[0].id, test.id]
                    );
                }
                console.log('   + Linked tests to first package');
            }
        } else {
            console.log('\n🔗 Package tests already linked or prerequisites missing. Skipping.');
        }

        // 4. Stores
        if (await isTableEmpty('stores')) {
            console.log('\n🏪 Stores table is empty. Inserting sample stores...');
            const stores = [
                { name: 'Pammal', city: 'Chennai', pincode: '600075', address: 'No.47, Ground Floor, Plot No.9, 10, 11, Muthamizh Nagar, Pammal Main Road, Pammal, Chennai – 600075', phone: '8925995441' },
                { name: 'Thiruverkadu', city: 'Chennai', pincode: '600077', address: 'No: 1, Sivan Koil Main Road, Thambusamy Nagar, Thiruverkadu, Chennai - 600077', phone: '8925995443' },
                { name: 'Pattabiram', city: 'Chennai', pincode: '600072', address: 'No. 763, Dandurai Village, C.T.C. Road, Pattabiram, Chennai – 600072', phone: '8925995442' }
            ];

            for (const store of stores) {
                await connection.query(
                    'INSERT INTO stores (name, city, pincode, address, phone, is_active) VALUES (?, ?, ?, ?, ?, ?)',
                    [store.name, store.city, store.pincode, store.address, store.phone, true]
                );
                process.stdout.write(`   + Added: ${store.name}\n`);
            }
        } else {
            console.log('\n🏪 Stores table already has data. Skipping insertion.');
        }

        // 5. Services
        if (await isTableEmpty('services')) {
            console.log('\n⚕️  Services table is empty. Inserting sample services...');
            const services = [
                { title: 'Home Collection', desc: 'Free sample collection at your doorstep', icon: '🏠', order: 1 },
                { title: 'NABL Accredited', desc: 'All our labs are NABL certified for quality', icon: '✅', order: 2 },
                { title: 'Quick Reports', desc: 'Get your reports within 24-48 hours', icon: '⚡', order: 3 },
                { title: 'Expert Consultation', desc: 'Free consultation with our healthcare experts', icon: '👨‍⚕️', order: 4 }
            ];

            for (const s of services) {
                await connection.query(
                    'INSERT INTO services (title, description, icon, display_order, is_active) VALUES (?, ?, ?, ?, ?)',
                    [s.title, s.desc, s.icon, s.order, true]
                );
                process.stdout.write(`   + Added: ${s.title}\n`);
            }
        } else {
            console.log('\n⚕️  Services table already has data. Skipping insertion.');
        }

        // ==========================================
        // DISPLAY DATA (Using SELECT as requested)
        // ==========================================
        console.log('\n' + '='.repeat(50));
        console.log('🔍 CURRENT DATABASE STATUS (SELECT * FROM ...)');
        console.log('='.repeat(50) + '\n');

        const displayTable = async (tableName, columns = '*') => {
            const [rows] = await connection.query(`SELECT ${columns} FROM ${tableName}`);
            console.log(`\n📊 Table: ${tableName.toUpperCase()} (${rows.length} records)`);
            if (rows.length > 0) {
                // Truncate long strings for better console display
                const truncated = rows.map(r => {
                    const obj = { ...r };
                    for (const k in obj) {
                        if (typeof obj[k] === 'string' && obj[k].length > 50) {
                            obj[k] = obj[k].substring(0, 47) + '...';
                        }
                    }
                    return obj;
                });
                console.table(truncated);
            } else {
                console.log('   (Empty)');
            }
        };

        await displayTable('tests', 'id, name, price, delivery_options');
        await displayTable('packages', 'id, name, price, delivery_options');
        await displayTable('stores', 'id, name, city, pincode, phone');
        await displayTable('services', 'id, title, is_active');

        console.log('\n✅ Verification Complete.');

    } catch (error) {
        console.error('❌ Error:', error.message);
        throw error;
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}

if (require.main === module) {
    populateTestData()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
} else {
    module.exports = populateTestData;
}
