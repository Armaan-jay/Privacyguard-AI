const http = require('http');

const tests = [
    // Should be LOW (legitimate)
    { url: 'https://accounts.google.com/login', expect: 'Low', label: 'accounts.google.com (legit)' },
    { url: 'https://amazon.co.uk/orders', expect: 'Low', label: 'amazon.co.uk (legit)' },
    { url: 'https://pay.paypal.com', expect: 'Low', label: 'pay.paypal.com (legit)' },
    { url: 'https://github.com', expect: 'Low', label: 'github.com (legit)' },
    { url: 'https://microsoft.com/en-us', expect: 'Low', label: 'microsoft.com (legit)' },
    // Should be HIGH (phishing)
    { url: 'br-icloud.com.br', expect: 'High', label: 'br-icloud.com.br (phishing)' },
    { url: 'http://paypa1-secure.xyz/verify-account', expect: 'High', label: 'paypa1 homoglyph (phishing)' },
    { url: 'http://192.168.99.1/suspend/update', expect: 'High', label: 'IP hostname (phishing)' },
    { url: 'http://apple-verify.login.secure.phish.com', expect: 'High', label: 'nested subdomain + brand (phishing)' },
    { url: 'amazon-support-suspended.tk', expect: 'High', label: 'amazon + bad TLD (phishing)' },
];

let done = 0;
tests.forEach(({ url, expect, label }, i) => {
    setTimeout(() => {
        const d = JSON.stringify({ url });
        const req = http.request({ host: 'localhost', port: 5000, path: '/api/scan-url', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(d) } }, (res) => {
            let out = ''; res.on('data', c => out += c);
            res.on('end', () => {
                const j = JSON.parse(out);
                const ok = j.risk_level === expect;
                const marker = ok ? '✅' : '❌';
                console.log(`${marker} [${j.risk_level}/${j.risk_score}] ${label}`);
                if (!ok) console.log(`   Expected: ${expect}, Got: ${j.risk_level}, Threats: ${j.threats?.map(t => t.type).join(', ')}`);
                if (++done === tests.length) process.exit(0);
            });
        });
        req.write(d); req.end();
    }, 300 + i * 200);
});
