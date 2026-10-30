const express = require('express');
const path = require('path');
const { generateWarpConfig, validateDomain } = require('./awg');

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/check-domain', async (req, res) => {
    try {
        const { domain } = req.body || {};
        const result = await validateDomain(domain);
        res.json(result);
    } catch (err) {
        console.error('check-domain error:', err);
        res.json({ valid: false, domain: 'www.cloudflare.com' });
    }
});

app.post('/api/generate', async (req, res) => {
    try {
        const { mode, ipRangeBase, i1 } = req.body || {};
        if (!i1) {
            return res.status(400).json({ success: false, message: 'Не передан I1' });
        }
        const conf = await generateWarpConfig({ mode, ipRangeBase, i1 });
        const content = Buffer.from(conf).toString('base64');
        res.json({ success: true, content });
    } catch (err) {
        console.error('generate error:', err);
        res.status(500).json({ success: false, message: 'Ошибка генерации' });
    }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`WARP random running on http://localhost:${PORT}`);
    });
}

module.exports = app;