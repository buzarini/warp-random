const express = require('express');
const path = require('path');
const fetch = require('node-fetch');
const { generateWarpConfig } = require('./awg');

const app = express();

app.use(express.static(path.join(__dirname, 'public')));

async function validateDomain(domain) {
    try {
        const rA = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
        const dA = await rA.json();
        if (dA.Answer && dA.Answer.some(a => a.type === 1)) return true;

        const rAAAA = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=AAAA`);
        const dAAAA = await rAAAA.json();
        if (dAAAA.Answer && dAAAA.Answer.some(a => a.type === 28)) return true;

        return false;
    } catch (e) {
        return false;
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/warp', async (req, res) => {
    try {
        let domain = (req.query.domain || '').toString().trim();
        if (!domain) domain = 'www.google.com';

        const level = Math.max(0, Math.min(4, parseInt(req.query.level, 10) ?? 4));
        const mode = ['auto', 'ip', 'domain'].includes(req.query.mode) ? req.query.mode : 'auto';
        const ipRange = req.query.ipRange || null;

        let useDomain = domain;
        let warning = null;

        if (domain !== 'www.google.com') {
            const valid = await validateDomain(domain);
            if (!valid) {
                warning = `Домен "${domain}" не существует.\nИспользован www.google.com`;
                useDomain = 'www.google.com';
            }
        }

        const conf = await generateWarpConfig({
            mode,
            ipRange,
            domain: useDomain,
            level,
        });
        const content = Buffer.from(conf, 'utf8').toString('base64');

        res.json({ success: true, content, warning });
    } catch (error) {
        console.error('Error generating config:', error);
        res.status(500).json({
            success: false,
            message: 'Не удалось сгенерировать конфиг',
        });
    }
});

// Local dev server
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}

module.exports = app;