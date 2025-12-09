const http = require('http');

http.get('http://localhost:5000/api/admin/debug-schema', (res) => {
    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });
    res.on('end', () => {
        try {
            const columns = JSON.parse(data);
            const customHtml = columns.find(c => c.Field === 'custom_html');
            console.log('custom_html column:', customHtml);
        } catch (e) {
            console.log('Raw data:', data);
        }
    });
}).on('error', (err) => {
    console.error('Error:', err.message);
});
