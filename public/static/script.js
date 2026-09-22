(function () {
    'use strict';

    const IP_RANGES = [
        '8.6.112', '8.34.70', '8.34.146', '8.35.211', '8.39.125', '8.39.204',
        '8.39.214', '8.47.69', '188.114.96', '188.114.97', '188.114.98', '188.114.99',
        '162.159.192', '162.159.195',
    ];

    const state = {
        mode: 'auto',
        generating: false,
        lastFilename: null,
        lastContent: null,
    };

    const $ = (id) => document.getElementById(id);
    const domainInput = $('domain');
    const clearBtn = $('clearDomain');
    const quicSelect = $('quicLevel');
    const panelBtns = document.querySelectorAll('.panel-btn');
    const ipRangeWrapper = $('ipRangeWrapper');
    const ipRangeSelect = $('ipRange');
    const generateBtn = $('generateBtn');
    const btnText = generateBtn.querySelector('.btn-text');
    const statusEl = $('status');

    // ---- Populate IP range select ----
    IP_RANGES.forEach((r) => {
        const opt = document.createElement('option');
        opt.value = r;
        opt.textContent = `${r}.0/24`;
        ipRangeSelect.appendChild(opt);
    });

    // ---- Helpers ----
    function normalizeDomain(input) {
        let s = (input || '').toString().trim();
        // remove protocol
        s = s.replace(/^[a-z][a-z0-9+\-.]*:\/\//i, '');
        // cut everything after : or /
        s = s.split(/[\/:]/)[0];
        return s;
    }

    function resetButton() {
        state.lastFilename = null;
        state.lastContent = null;
        btnText.textContent = 'Сгенерировать';
        generateBtn.disabled = false;
        generateBtn.classList.remove('loading');
        generateBtn.onclick = generate;
    }

    function showStatus(text, type) {
        statusEl.textContent = text;
        statusEl.className = 'status visible ' + (type || '');
    }

    function hideStatus() {
        statusEl.textContent = '';
        statusEl.className = 'status';
    }

    function resetAll() {
        resetButton();
        hideStatus();
    }

    function downloadConfig() {
        if (!state.lastContent || !state.lastFilename) return;
        const link = document.createElement('a');
        link.href = 'data:application/octet-stream;base64,' + state.lastContent;
        link.download = state.lastFilename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    // ---- Generation ----
    async function generate() {
        if (state.generating) return;
        state.generating = true;

        generateBtn.disabled = true;
        generateBtn.classList.add('loading');
        generateBtn.onclick = null;
        btnText.textContent = 'Генерация...';

        const domain = normalizeDomain(domainInput.value) || 'www.google.com';
        const level = quicSelect.value;
        const mode = state.mode;
        const ipRange = ipRangeSelect.value;

        const params = new URLSearchParams({ domain, level, mode });
        if (mode === 'ip' && ipRange) params.set('ipRange', ipRange);

        try {
            const r = await fetch('/warp?' + params.toString());
            const data = await r.json();

            if (!data.success) {
                showStatus(data.message || 'Ошибка генерации', 'error');
                resetButton();
                return;
            }

            const filename = `WARP_${Math.floor(Math.random() * 90) + 10}.conf`;
            state.lastFilename = filename;
            state.lastContent = data.content;

            if (data.warning) {
                showStatus(data.warning, 'error');
            } else {
                showStatus(`Конфиг ${filename} успешно создан`, 'success');
            }

            btnText.textContent = filename;
            generateBtn.disabled = false;
            generateBtn.classList.remove('loading');
            generateBtn.onclick = downloadConfig;

            downloadConfig();
        } catch (e) {
            console.error(e);
            showStatus('Ошибка соединения с сервером', 'error');
            resetButton();
        } finally {
            state.generating = false;
            generateBtn.classList.remove('loading');
        }
    }

    // ---- Domain input events ----
    domainInput.addEventListener('input', () => {
        resetAll();
    });

    domainInput.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData('text');
        domainInput.value = normalizeDomain(text);
        resetAll();
    });

    domainInput.addEventListener('blur', () => {
        const normalized = normalizeDomain(domainInput.value);
        if (normalized !== domainInput.value) {
            domainInput.value = normalized;
            resetAll();
        }
    });

    clearBtn.addEventListener('click', () => {
        domainInput.value = '';
        resetAll();
        domainInput.focus();
    });

    // ---- QUIC level ----
    quicSelect.addEventListener('change', () => {
        resetAll();
    });

    // ---- Panel buttons ----
    panelBtns.forEach((btn) => {
        btn.addEventListener('click', () => {
            panelBtns.forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            state.mode = btn.dataset.mode;

            if (state.mode === 'ip') {
                ipRangeWrapper.classList.add('visible');
            } else {
                ipRangeWrapper.classList.remove('visible');
            }
            resetAll();
        });
    });

    ipRangeSelect.addEventListener('change', () => {
        resetAll();
    });

    // ---- Init ----
    generateBtn.onclick = generate;
})();