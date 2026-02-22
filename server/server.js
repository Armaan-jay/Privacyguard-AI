
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import gplay from 'google-play-scraper';
import axios from 'axios';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

app.use(cors());
app.use(bodyParser.json());

app.post('/api/assess', (req, res) => {
    const { name, description, permissions } = req.body;

    if (!name || !description) {
        return res.status(400).json({ error: 'Name and description are required.' });
    }

    // Path to Python script
    const scriptPath = path.join(__dirname, '../ml/predict.py');
    const pythonExecutable = 'python'; // Or full path to python if needed

    const pythonProcess = spawn(pythonExecutable, [scriptPath, name, description, permissions || '']);

    let dataString = '';
    let errorString = '';

    pythonProcess.stdout.on('data', (data) => {
        dataString += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        errorString += data.toString();
    });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            console.error(`Python script exited with code ${code}`);
            console.error(errorString);
            return res.status(500).json({ error: 'Internal server error during risk assessment.' });
        }

        try {
            const result = JSON.parse(dataString);
            res.json(result);
        } catch (e) {
            console.error('Error parsing JSON from Python script:', e);
            console.error('Raw output:', dataString);
            res.status(500).json({ error: 'Failed to parse risk assessment result.' });
        }
    });
});

// URL / Domain AI Scanner (DistilBERT â€” kmack/malicious-url-detection)
// For URLs and domains ONLY â€” NOT APK filenames
app.post('/api/scan', (req, res) => {
    const { input } = req.body;
    if (!input || !input.trim()) {
        return res.status(400).json({ error: 'URL or domain is required.' });
    }

    const scriptPath = path.join(__dirname, '../ml/hf_predict.py');
    const pythonProcess = spawn('python', [scriptPath, input.trim()]);

    let dataString = '';
    let errorString = '';

    pythonProcess.stdout.on('data', (data) => { dataString += data.toString(); });
    pythonProcess.stderr.on('data', (data) => { errorString += data.toString(); });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            console.error('hf_predict.py error:', errorString);
            return res.status(500).json({ error: 'AI model scan failed.', detail: errorString.slice(0, 300) });
        }
        try {
            const result = JSON.parse(dataString);
            res.json(result);
        } catch (e) {
            res.status(500).json({ error: 'Failed to parse AI model output.' });
        }
    });
});

// APK Filename Heuristic Scanner
// Purpose-built APK checks â€” NOT the URL model (URL models flag all APK filenames as malicious)
app.post('/api/scan-apk', async (req, res) => {
    const { filename } = req.body;
    if (!filename || !filename.trim()) {
        return res.status(400).json({ error: 'Filename is required.' });
    }

    const raw = filename.trim();

    // Validate: must end with .apk
    if (!raw.toLowerCase().endsWith('.apk')) {
        return res.status(400).json({
            error: 'invalid_apk',
            message: `"${raw}" is not a valid APK file. The filename must end with .apk (e.g. WhatsApp.apk)`
        });
    }

    const lower = raw.toLowerCase().replace(/[\s_\-]+/g, ' ');
    const lowerNoSpace = raw.toLowerCase().replace(/[\s_\-]+/g, '');
    const threats = [];
    let riskScore = 0;

    // Extract base name and version
    const versionMatch = raw.match(/[_\-\s]v?(\d+[\.\d]*)(?:[_\-\s]|\.apk)/i);
    const version = versionMatch ? versionMatch[1] : null;
    // Clean up name: remove version, crack keywords for cleaner search query
    const baseName = raw.replace(/\.apk$/i, '').replace(/[_\-\s]+v?\d+[\.\d]*/i, '').trim();
    const searchQuery = baseName
        .replace(/[_\-]+/g, ' ')
        .replace(/\b(mod|cracked|hack|unlimited|unlocked|patched|premium|pro|free|full)\b/gi, '')
        .replace(/\s+/g, ' ').trim();

    // ── Play Store Existence Check ─────────────────────────────────────────
    // Check if any app on the Play Store matches this filename's app name
    let ps_match = null;
    let playStoreVerified = false;
    try {
        // If filename looks like a package ID (com.xxx.apk), try direct lookup first
        const isPackageId = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.apk$/i.test(raw);
        if (isPackageId) {
            const pkgId = raw.replace(/\.apk$/i, '');
            try {
                const appData = await gplay.app({ appId: pkgId, lang: 'en', country: 'us' });
                ps_match = { title: appData.title, developer: appData.developer, appId: pkgId, score: appData.scoreText };
                playStoreVerified = true;
            } catch (e) { /* not found by package ID, fall through to search */ }
        }

        if (!playStoreVerified && searchQuery.length >= 2) {
            const results = await gplay.search({ term: searchQuery, num: 5, lang: 'en', country: 'us' });
            // Look for a result whose title closely matches the search query (case-insensitive)
            const match = results.find(r =>
                r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                searchQuery.toLowerCase().includes(r.title.toLowerCase().slice(0, 6))
            );
            if (match) {
                ps_match = { title: match.title, developer: match.developer, appId: match.appId, score: match.scoreText };
                playStoreVerified = true;
            }
        }
    } catch (e) {
        // Play Store unreachable — don't block the scan, just mark as unverified
        console.warn('Play Store lookup failed:', e.message);
    }

    // If the app genuinely cannot be found on the Play Store, flag it
    if (!playStoreVerified && searchQuery.length >= 3) {
        return res.status(404).json({
            error: 'apk_not_found',
            message: `No app matching "${searchQuery}" was found on the Google Play Store. This APK may be from an unofficial or malicious source.`,
            filename: raw,
            app_name: baseName
        });
    }

    // CHECK 1: Modded / cracked indicators
    const crackPatterns = ['mod', 'cracked', 'crack', 'patched', 'patch', 'hack', 'hacked',
        'unlimited', 'unlocked', 'premium', 'pro unlocked', 'full version', 'no ads',
        'generator', 'cheat', 'cheats', 'injector', 'spoofer', 'bypass'];
    for (const p of crackPatterns) {
        if (lower.includes(p)) {
            threats.push({ type: 'Modded / Cracked APK', severity: 'Critical', message: `Contains "${p}" â€” modded APKs are repackaged with malicious code, adware, or spyware.` });
            riskScore += 60; break;
        }
    }

    // CHECK 2: Fake system / OS update (CamelCase-aware)
    const systemFakePatterns = ['system update', 'android update', 'google update',
        'play store update', 'security patch', 'firmware update', 'os update'];
    for (const p of systemFakePatterns) {
        const pNoSpace = p.replace(/\s/g, '');
        if (lower.includes(p) || lowerNoSpace.includes(pNoSpace)) {
            threats.push({ type: 'Fake System App', severity: 'Critical', message: `"${p}" â€” malware disguised as a system/OS update. Legitimate updates never come as APK files.` });
            riskScore += 65; break;
        }
    }

    // CHECK 3: Banking / UPI / financial impersonation
    const financePatterns = ['paytm', 'phonepe', 'gpay', 'google pay', 'bhim', 'upi',
        'netbanking', 'banking', 'sbi', 'hdfc', 'icici', 'axis bank', 'kotak',
        'rbi', 'income tax', 'epfo', 'aadhaar', 'pan card'];
    for (const p of financePatterns) {
        if (lower.includes(p)) {
            threats.push({ type: 'Financial App Impersonation', severity: 'High', message: `Contains "${p}" â€” fake banking/UPI apps steal credentials and commit financial fraud.` });
            riskScore += 50; break;
        }
    }

    // CHECK 4: Government app impersonation
    const govPatterns = ['rto', 'challan', 'digilocker', 'mparivahan', 'aarogya setu',
        'umang', 'cowin', 'e-challan', 'sarkar', 'income tax', 'epfo'];
    for (const p of govPatterns) {
        if (lower.includes(p)) {
            threats.push({ type: 'Government App Impersonation', severity: 'High', message: `Contains "${p}" â€” fake government apps are used for data harvesting and scams.` });
            riskScore += 45; break;
        }
    }

    // CHECK 5: Suspiciously high version number
    if (version) {
        const major = parseInt(version.split('.')[0], 10);
        if (major > 50) {
            threats.push({ type: 'Suspicious Version Number', severity: 'Medium', message: `Version ${version} is abnormally high. Legitimate apps rarely exceed v50.` });
            riskScore += 20;
        }
    }

    // CHECK 6: No version info at all (only flag for longer names that should have versions)
    if (!version && baseName.length > 15) {
        threats.push({ type: 'Missing Version Info', severity: 'Low', message: 'APK has no version number â€” legitimate apps typically include versioning.' });
        riskScore += 8;
    }

    // CHECK 7: Known malware family names
    const malwareNames = ['spynote', 'flubot', 'sharkbot', 'cerberus', 'joker',
        'hydra', 'anubis', 'ginp', 'eventbot', 'alien', 'medusa', 'ermac'];
    for (const m of malwareNames) {
        if (lowerNoSpace.includes(m)) {
            threats.push({ type: 'Known Malware Family', severity: 'Critical', message: `Matches known Android malware family name: "${m}".` });
            riskScore += 80; break;
        }
    }

    // CHECK 8: Popular app + mod keyword combined
    const popularApps = ['whatsapp', 'instagram', 'facebook', 'telegram', 'snapchat',
        'tiktok', 'youtube', 'pubg', 'freefire', 'netflix', 'spotify'];
    const hasModKeyword = crackPatterns.some(p => lower.includes(p));
    for (const appName of popularApps) {
        if (lower.includes(appName) && hasModKeyword) {
            threats.push({ type: 'Popular App Impersonation', severity: 'High', message: `Impersonates "${appName}" with modification keywords â€” used to distribute spyware.` });
            riskScore += 40; break;
        }
    }

    // CHECK 9: Unusual / obfuscated characters
    if (/[^\w\s\-\.\(\)\[\]]/u.test(raw.replace(/\.apk$/i, ''))) {
        threats.push({ type: 'Obfuscated Filename', severity: 'Medium', message: 'Filename contains unusual characters â€” may indicate obfuscation to bypass security filters.' });
        riskScore += 15;
    }

    // CHECK 10: Anomalous name length
    const nameLen = baseName.replace(/\.apk$/i, '').length;
    if (nameLen < 3) {
        threats.push({ type: 'Suspiciously Short Name', severity: 'Medium', message: 'Filename is unusually short â€” legitimate apps typically have descriptive names.' });
        riskScore += 12;
    } else if (nameLen > 80) {
        threats.push({ type: 'Suspiciously Long Name', severity: 'Low', message: 'Filename is unusually long â€” may hide the true name in a wall of text.' });
        riskScore += 8;
    }

    riskScore = Math.min(riskScore, 100);
    const risk_level = riskScore >= 55 ? 'High' : riskScore >= 25 ? 'Medium' : 'Low';

    res.json({
        filename: raw,
        app_name: baseName,
        version: version || 'Unknown',
        play_store_verified: playStoreVerified,
        ps_match,
        risk_level,
        risk_score: riskScore,
        confidence: {
            malicious: parseFloat((riskScore / 100).toFixed(2)),
            benign: parseFloat((1 - riskScore / 100).toFixed(2))
        },
        threats
    });
});


app.post('/api/fetch-app', async (req, res) => {
    const { appId } = req.body;
    if (!appId) return res.status(400).json({ error: 'App ID is required' });

    try {
        // Fetch app metadata
        const appData = await gplay.app({ appId: appId, lang: 'en', country: 'us' });

        // Fetch permissions separately (gplay.app() does not reliably include them)
        let permissionsList = [];
        try {
            const permsData = await gplay.permissions({ appId: appId, lang: 'en', short: false });
            permissionsList = permsData.map(p => p.permission || p).filter(Boolean);
        } catch (permErr) {
            // Permissions may not be publicly available â€” not fatal
            console.warn(`Could not fetch permissions for ${appId}:`, permErr.message);
        }

        res.json({
            name: appData.title,
            description: appData.descriptionText || appData.description || '',
            permissions: permissionsList.join(', '),
            icon: appData.icon,
            developer: appData.developer,
            score: appData.scoreText || appData.score?.toFixed(1) || 'N/A',
            reviews: appData.reviews || 0,
            installs: appData.installs || 'Unknown',
            updated: appData.updated || 'Unknown'
        });
    } catch (error) {
        console.error('Error fetching app data:', error.message);
        // Distinguish between "not found" and network errors
        const isNotFound = error.message?.toLowerCase().includes('not found') ||
            error.message?.toLowerCase().includes('404') ||
            error.message?.toLowerCase().includes('app not found');
        const status = isNotFound ? 404 : 502;
        const message = isNotFound
            ? `App "${appId}" was not found on the Play Store. Check that the package ID is correct (e.g. com.whatsapp).`
            : `Could not reach the Play Store right now. Check your internet connection and try again.`;
        res.status(status).json({ error: message });
    }
});

// Ghost Page Scanner Endpoint
app.post('/api/scan-ghost-pages', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    // Step 1: Validate URL format
    let parsedUrl;
    try {
        const rawUrl = url.startsWith('http') ? url : `https://${url}`;
        parsedUrl = new URL(rawUrl);
    } catch (e) {
        return res.status(400).json({
            error: 'invalid_url',
            message: `"${url}" is not a valid URL. Please enter a proper domain like https://example.com`
        });
    }

    // Step 2: Check if the domain actually resolves/responds
    const baseUrl = parsedUrl.origin; // e.g. "https://example.com"
    try {
        await axios.get(baseUrl, {
            validateStatus: () => true, // accept any status, even 4xx/5xx - domain still exists
            timeout: 6000,
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' }
        });
    } catch (err) {
        // DNS resolution failure, connection refused, or timeout = domain doesn't exist
        const isTimeout = err.code === 'ECONNABORTED';
        const isDNSFail = err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN';
        const isRefused = err.code === 'ECONNREFUSED';
        let message = `Cannot reach "${parsedUrl.hostname}". `;
        if (isDNSFail) message += 'Domain does not exist or DNS failed to resolve.';
        else if (isRefused) message += 'Connection was refused by the server.';
        else if (isTimeout) message += 'The server did not respond in time.';
        else message += 'The URL is unreachable. Check if the site is online.';
        return res.status(400).json({ error: 'unreachable_url', message });
    }

    // Comprehensive path list with risk categorization
    const pathsRiskMap = [
        // Critical - Authentication & Admin
        { path: '/admin', risk: 'High', category: 'Admin Panel' },
        { path: '/administrator', risk: 'High', category: 'Admin Panel' },
        { path: '/wp-admin', risk: 'High', category: 'Admin Panel' },
        { path: '/admin/login', risk: 'High', category: 'Admin Panel' },
        { path: '/controlpanel', risk: 'High', category: 'Admin Panel' },
        { path: '/cpanel', risk: 'High', category: 'Admin Panel' },
        { path: '/manage', risk: 'High', category: 'Admin Panel' },
        { path: '/management', risk: 'High', category: 'Admin Panel' },
        { path: '/phpmyadmin', risk: 'High', category: 'Database UI' },
        { path: '/mysql', risk: 'High', category: 'Database UI' },
        { path: '/adminer', risk: 'High', category: 'Database UI' },
        { path: '/dbadmin', risk: 'High', category: 'Database UI' },
        // Backup & Configuration Files
        { path: '/backup', risk: 'High', category: 'Backup File' },
        { path: '/backup.zip', risk: 'High', category: 'Backup File' },
        { path: '/backup.sql', risk: 'High', category: 'Backup File' },
        { path: '/dump.sql', risk: 'High', category: 'Backup File' },
        { path: '/db.sql', risk: 'High', category: 'Backup File' },
        { path: '/config', risk: 'High', category: 'Config File' },
        { path: '/config.php', risk: 'High', category: 'Config File' },
        { path: '/config.json', risk: 'High', category: 'Config File' },
        { path: '/.env', risk: 'High', category: 'Config File' },
        { path: '/.env.local', risk: 'High', category: 'Config File' },
        { path: '/.env.production', risk: 'High', category: 'Config File' },
        { path: '/wp-config.php', risk: 'High', category: 'Config File' },
        { path: '/settings.php', risk: 'High', category: 'Config File' },
        { path: '/secrets.json', risk: 'High', category: 'Config File' },
        // Developer / Debug Endpoints
        { path: '/test', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/dev', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/debug', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/temp', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/old', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/staging', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/beta', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/demo', risk: 'Medium', category: 'Dev/Test Page' },
        { path: '/console', risk: 'High', category: 'Dev/Test Page' },
        { path: '/shell', risk: 'High', category: 'Dev/Test Page' },
        // API Endpoints
        { path: '/api', risk: 'Medium', category: 'API Endpoint' },
        { path: '/api/v1', risk: 'Medium', category: 'API Endpoint' },
        { path: '/api/v2', risk: 'Medium', category: 'API Endpoint' },
        { path: '/graphql', risk: 'Medium', category: 'API Endpoint' },
        { path: '/swagger', risk: 'Medium', category: 'API Endpoint' },
        { path: '/swagger-ui.html', risk: 'Medium', category: 'API Endpoint' },
        { path: '/api-docs', risk: 'Medium', category: 'API Endpoint' },
        { path: '/openapi.json', risk: 'Medium', category: 'API Endpoint' },
        // Authentication Pages
        { path: '/login', risk: 'Low', category: 'Auth Page' },
        { path: '/signup', risk: 'Low', category: 'Auth Page' },
        { path: '/register', risk: 'Low', category: 'Auth Page' },
        { path: '/user', risk: 'Low', category: 'Auth Page' },
        { path: '/users', risk: 'Low', category: 'Auth Page' },
        { path: '/dashboard', risk: 'Medium', category: 'Auth Page' },
        { path: '/profile', risk: 'Low', category: 'Auth Page' },
        // Public Info Disclosure
        { path: '/robots.txt', risk: 'Low', category: 'Info Disclosure' },
        { path: '/sitemap.xml', risk: 'Low', category: 'Info Disclosure' },
        { path: '/.git', risk: 'High', category: 'Info Disclosure' },
        { path: '/.git/config', risk: 'High', category: 'Info Disclosure' },
        { path: '/phpinfo.php', risk: 'High', category: 'Info Disclosure' },
        { path: '/server-status', risk: 'High', category: 'Info Disclosure' },
        { path: '/info.php', risk: 'High', category: 'Info Disclosure' },
        { path: '/crossdomain.xml', risk: 'Low', category: 'Info Disclosure' },
        // CMS-Specific
        { path: '/wp-login.php', risk: 'Medium', category: 'CMS' },
        { path: '/wp-content/uploads', risk: 'Medium', category: 'CMS' },
        { path: '/xmlrpc.php', risk: 'High', category: 'CMS' },
        { path: '/joomla', risk: 'Medium', category: 'CMS' },
        { path: '/drupal', risk: 'Medium', category: 'CMS' },
        // Logs / Data Leakage
        { path: '/logs', risk: 'High', category: 'Log File' },
        { path: '/error.log', risk: 'High', category: 'Log File' },
        { path: '/access.log', risk: 'High', category: 'Log File' },
        { path: '/debug.log', risk: 'High', category: 'Log File' },
        { path: '/laravel.log', risk: 'High', category: 'Log File' },
    ];

    const results = [];
    const scanBase = parsedUrl.origin;

    try {
        const promises = pathsRiskMap.map(async ({ path: p, risk, category }) => {
            try {
                const targetUrl = `${scanBase}${p}`;
                const response = await axios.get(targetUrl, {
                    validateStatus: () => true,
                    timeout: 4000,
                    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' }
                });

                if (response.status === 200) {
                    const bodySnippet = typeof response.data === 'string'
                        ? response.data.substring(0, 500).toLowerCase() : '';

                    // Bump to High if body contains admin keywords
                    let finalRisk = risk;
                    if (['Medium', 'Low'].includes(risk)) {
                        if (bodySnippet.includes('password') || bodySnippet.includes('login') ||
                            bodySnippet.includes('admin') || bodySnippet.includes('phpmyadmin') ||
                            bodySnippet.includes('index of /')) {
                            finalRisk = 'High';
                        }
                    }
                    results.push({ path: p, status: response.status, risk: finalRisk, category });
                }
            } catch (err) { /* ignore timeout/refused */ }
        });

        await Promise.all(promises);
        // Sort by risk: High first
        results.sort((a, b) => ({ High: 0, Medium: 1, Low: 2 }[a.risk] - { High: 0, Medium: 1, Low: 2 }[b.risk]));
        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Code Security Lint Endpoint
app.post('/api/scan-code', (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code snippet is required' });

    const vulnerabilities = [];
    const lines = code.split('\n');

    const rules = [
        // --- Hardcoded Secrets ---
        { regex: /AKIA[0-9A-Z]{16}/, type: 'Hardcoded Secret', severity: 'Critical', message: 'AWS Access Key ID detected. Immediately revoke and rotate this key.' },
        { regex: /sk_live_[0-9a-zA-Z]{24,}/, type: 'Hardcoded Secret', severity: 'Critical', message: 'Stripe Live Secret Key detected. Revoke immediately.' },
        { regex: /(api_key|apikey|api_secret|secret_key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/, type: 'Hardcoded Secret', severity: 'High', message: 'Hardcoded API key/secret. Use environment variables instead.' },
        { regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/, type: 'Hardcoded Password', severity: 'Critical', message: 'Hardcoded password detected. Store credentials securely in a secrets manager.' },
        { regex: /BEGIN (RSA|EC|OPENSSH) PRIVATE KEY/, type: 'Hardcoded Secret', severity: 'Critical', message: 'Private key embedded in source code. Remove immediately.' },
        { regex: /ghp_[A-Za-z0-9]{36}/, type: 'Hardcoded Secret', severity: 'Critical', message: 'GitHub Personal Access Token detected.' },
        // --- Injection Attacks ---
        { regex: /eval\s*\(/, type: 'Code Injection', severity: 'High', message: 'eval() executes arbitrary code. Replace with a safe parser.' },
        { regex: /exec\s*\(/, type: 'Command Injection', severity: 'High', message: 'exec() allows OS command injection. Use safer subprocess alternatives.' },
        { regex: /os\.system\s*\(/, type: 'Command Injection', severity: 'High', message: 'os.system() is vulnerable to command injection. Use subprocess.run() with a list instead.' },
        { regex: /subprocess\.call\(['"]/, type: 'Command Injection', severity: 'Medium', message: 'subprocess.call with a string argument can be vulnerable. Pass a list of arguments instead.' },
        { regex: /child_process\.exec\s*\(/, type: 'Command Injection', severity: 'High', message: 'child_process.exec is vulnerable to shell injection. Use execFile() or spawn() instead.' },
        { regex: /SELECT\s+.*\s+FROM\s+.*\+|SELECT\s+.*\s+FROM\s+.*`/, type: 'SQL Injection', severity: 'Critical', message: 'Possible SQL Injection via string concatenation. Use parameterized queries / prepared statements.' },
        { regex: /db\.query\(['"]SELECT.*\+/, type: 'SQL Injection', severity: 'Critical', message: 'SQL query built with string concatenation. Use parameterized queries.' },
        // --- XSS Vulnerabilities ---
        { regex: /\.innerHTML\s*=/, type: 'XSS', severity: 'High', message: 'Direct innerHTML assignment can cause XSS. Use textContent or sanitize with DOMPurify.' },
        { regex: /dangerouslySetInnerHTML/, type: 'XSS', severity: 'High', message: 'dangerouslySetInnerHTML can expose XSS. Sanitize the input with a library like DOMPurify.' },
        { regex: /document\.write\s*\(/, type: 'XSS', severity: 'Medium', message: 'document.write() can cause XSS and blocks rendering. Use DOM manipulation methods instead.' },
        { regex: /\.outerHTML\s*=/, type: 'XSS', severity: 'High', message: 'outerHTML assignment can cause XSS. Sanitize input first.' },
        // --- Path Traversal ---
        { regex: /\.\.\/|\.\.\\/g, type: 'Path Traversal', severity: 'High', message: 'Path traversal sequence detected. Validate and sanitize file paths.' },
        { regex: /open\([^)]*\+[^)]*\)/, type: 'Path Traversal', severity: 'Medium', message: 'Dynamic file path construction. Validate paths against an allowlist.' },
        // --- Weak Cryptography ---
        { regex: /md5\s*\(|hashlib\.md5\s*\(|createHash\(['"]md5['"]\)/, type: 'Weak Cryptography', severity: 'High', message: 'MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords.' },
        { regex: /sha1\s*\(|hashlib\.sha1\s*\(|createHash\(['"]sha1['"]\)/, type: 'Weak Cryptography', severity: 'Medium', message: 'SHA-1 is deprecated and weak. Use SHA-256 or stronger.' },
        { regex: /DES|RC4|TripleDES/, type: 'Weak Cryptography', severity: 'High', message: 'Deprecated cipher algorithm detected. Use AES-256-GCM.' },
        // --- Insecure Configurations ---
        { regex: /verify\s*=\s*False|VERIFY_SSL\s*=\s*False|rejectUnauthorized\s*:\s*false/, type: 'Insecure Config', severity: 'High', message: 'SSL certificate verification is disabled. This allows MITM attacks.' },
        { regex: /httpOnly\s*:\s*false|httponly\s*=\s*false/, type: 'Insecure Cookie', severity: 'Medium', message: 'HttpOnly flag is disabled. Cookies are accessible via JavaScript (XSS risk).' },
        { regex: /secure\s*:\s*false/, type: 'Insecure Cookie', severity: 'Medium', message: 'Secure flag is disabled. Cookie will be sent over HTTP.' },
        { regex: /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\]|cors\(\{\s*origin:\s*['"]\*['"]/, type: 'Insecure Config', severity: 'Medium', message: 'Wildcard CORS/ALLOWED_HOSTS origin. Restrict to specific trusted domains.' },
        // --- Prototype Pollution ---
        { regex: /__proto__|constructor\[.*\]\s*=|prototype\[.*\]\s*=/, type: 'Prototype Pollution', severity: 'High', message: 'Possible prototype pollution attack vector. Validate and sanitize object keys.' },
        // --- Misc ---
        { regex: /TODO.*auth|FIXME.*security|HACK.*bypass/, type: 'Security TODO', severity: 'Low', message: 'Security-related TODO/FIXME comment found. Ensure this is addressed before release.' },
        { regex: /console\.log\(.*password|console\.log\(.*token|console\.log\(.*secret/, type: 'Sensitive Data Leak', severity: 'Medium', message: 'Sensitive data possibly logged to console. Remove before production.' },
    ];

    lines.forEach((line, index) => {
        rules.forEach(rule => {
            if (rule.regex.test(line)) {
                vulnerabilities.push({
                    line: index + 1,
                    content: line.trim(),
                    type: rule.type,
                    severity: rule.severity,
                    message: rule.message
                });
            }
        });
    });

    res.json({ vulnerabilities, totalScanned: lines.length, totalRules: rules.length });
});

// OSINT Username Search Endpoint
app.post('/api/osint-search', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });

    const platforms = [
        {
            name: 'GitHub',
            url: `https://github.com/${username}`,
            // GitHub returns 404 for non-existent users - status check is reliable
            existsCheck: (status, body) => status === 200 && !body.includes('Not Found'),
            risk: 'High',
            analysis: 'Exposes code, email addresses, contribution history, and potential leaked secrets in repos.',
            remediation: 'Audit public repos for secrets. Enable 2FA. Request data removal via GitHub Privacy.'
        },
        {
            name: 'Reddit',
            url: `https://www.reddit.com/user/${username}/about.json`,
            // Use JSON API - returns 404 for non-existent users without HTML ambiguity
            existsCheck: (status, body) => status === 200 && body.includes('"name"'),
            risk: 'Medium',
            analysis: 'Post/comment history can reveal opinions, location, personal details, and browsing habits.',
            remediation: 'Delete posts with tools like Redact.dev. Delete account via Reddit Settings.'
        },
        {
            name: 'Instagram',
            url: `https://www.instagram.com/${username}/?__a=1`,
            // Parse response body to confirm actual profile existence
            existsCheck: (status, body) => status === 200 && !body.includes('"not_found"') && !body.toLowerCase().includes('sorry, this page'),
            risk: 'High',
            analysis: 'Photos expose location metadata, lifestyle patterns, social connections, and daily routines.',
            remediation: 'Set to Private. Remove location tags from posts. Delete via Instagram Help Center.'
        },
        {
            name: 'Twitter / X',
            url: `https://twitter.com/${username}`,
            existsCheck: (status, body) => status === 200 && !body.includes('This account doesn') && !body.toLowerCase().includes('doesn\'t exist'),
            risk: 'High',
            analysis: 'Tweets can reveal location, political views, employers, and real-time whereabouts.',
            remediation: 'Lock your account or permanently delete via Settings > Account > Deactivate.'
        },
        {
            name: 'Pinterest',
            url: `https://www.pinterest.com/${username}/`,
            existsCheck: (status, body) => status === 200 && !body.toLowerCase().includes('sorry! the page you') && !body.toLowerCase().includes('page not found'),
            risk: 'Low',
            analysis: 'Pinboards can reveal interests, wishlist items, and life events.',
            remediation: 'Deactivate account in Settings > Account Management.'
        },
        {
            name: 'Twitch',
            url: `https://www.twitch.tv/${username}`,
            existsCheck: (status, body) => status === 200 && !body.toLowerCase().includes('sorry. unless') && !body.toLowerCase().includes('page not found'),
            risk: 'Medium',
            analysis: 'Live stream schedules and chat logs reveal active hours, interests, and personal details shared on stream.',
            remediation: 'Disable VOD/clip storage. Delete account under Settings > Security and Privacy.'
        },
        {
            name: 'Steam',
            url: `https://steamcommunity.com/id/${username}`,
            existsCheck: (status, body) => status === 200 && !body.toLowerCase().includes('the specified profile could not be found'),
            risk: 'Low',
            analysis: 'Public gaming profiles expose friends list, game history, activity patterns, and profile bio.',
            remediation: 'Set to Private in Edit Profile > Privacy Settings.'
        },
        {
            name: 'Keybase',
            url: `https://keybase.io/${username}`,
            existsCheck: (status, body) => status === 200 && !body.toLowerCase().includes('page was not found'),
            risk: 'Medium',
            analysis: 'Links multiple social accounts and public keys revealing a full digital identity graph.',
            remediation: 'Delete your Keybase account via Settings > Account > Delete.'
        },
        {
            name: 'Gravatar',
            url: `https://en.gravatar.com/${username}`,
            existsCheck: (status, body) => status === 200 && !body.toLowerCase().includes('profile not found'),
            risk: 'Low',
            analysis: 'Avatar and real name linked to email address used across websites.',
            remediation: 'Remove personal info from Gravatar profile or delete via Account Settings.'
        },
        {
            name: 'HackerNews',
            url: `https://news.ycombinator.com/user?id=${username}`,
            existsCheck: (status, body) => status === 200 && body.includes('user?id='),
            risk: 'Low',
            analysis: 'Comment history, karma score, and links submitted reveal technical expertise and interests.',
            remediation: 'Comments cannot be deleted. Email hn@ycombinator.com for account removal.'
        },
    ];

    const results = [];

    try {
        const promises = platforms.map(async (platform) => {
            try {
                const response = await axios.get(platform.url, {
                    validateStatus: () => true,
                    timeout: 6000,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                });

                const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                const profileExists = platform.existsCheck(response.status, body);

                if (profileExists) {
                    results.push({
                        platform: platform.name,
                        url: platform.url.split('?')[0], // Clean URL for display
                        found: true,
                        risk: platform.risk,
                        analysis: platform.analysis,
                        remediation: platform.remediation
                    });
                }
            } catch (err) { /* Ignore connection errors */ }
        });

        await Promise.all(promises);
        // Sort by risk: High first
        results.sort((a, b) => ({ High: 0, Medium: 1, Low: 2 }[a.risk] - { High: 0, Medium: 1, Low: 2 }[b.risk]));
        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: 'OSINT scan failed' });
    }
});

// LLM Security Scanner Proxy
app.post('/api/scan-llm', async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

    try {
        const response = await axios.post('http://localhost:8000/analyze', { prompt });
        res.json(response.data);
    } catch (err) {
        console.error('LLM Engine Error:', err.message);
        if (err.code === 'ECONNREFUSED') {
            return res.status(503).json({
                error: 'LLM Engine is offline',
                details: 'Please start the Python service (python llm_engine/main.py)'
            });
        }
        res.status(500).json({ error: 'Failed to analyze prompt' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

