const net = require('net');

const ports = [21, 23, 80, 8080, 8443, 6379, 27017, 3306];

ports.forEach(port => {
    const server = net.createServer((socket) => {
        socket.on('error', (err) => {
            // Ignore socket errors during scan
        });
        socket.write('SecOps Test Environment\r\n');
        if (port === 23) {
            socket.write('User: ');
        }
        socket.end();
    });

    server.on('error', (err) => {
        console.warn(`Could not start listener on port ${port}: ${err.message}`);
    });

    server.listen(port, '127.0.0.1', () => {
        console.log(`Port ${port} is now open for simulation...`);
    });
});
