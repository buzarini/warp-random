(function () {
    'use strict';

    let currentMode = 'auto';
    let generatedFileName = null;
    let generatedFileContent = null;
    let isGenerating = false;

    /* ---------- helpers ---------- */

    function cleanDomain(input) {
        let s = (input || '').trim();
        if (!s) return '';
        s = s.replace(/^https?:\/\//i, '');
        s = s.split('/')[0];
        s = s.split(':')[0];
        s = s.split('?')[0];
        s = s.split('#')[0];
        return s.toLowerCase();
    }

    function setStatus(message, isError) {
        const status = document.getElementById('status');
        status.textContent = message;
        status.classList.remove('hidden');
        status.classList.toggle('error', !!isError);
    }

    function hideStatus() {
        const status = document.getElementById('status');
        status.classList.add('hidden');
        status.classList.remove('error');
        status.textContent = '';
    }

    function resetGeneration() {
        if (isGenerating) return;
        generatedFileName = null;
        generatedFileContent = null;

        const btn = document.getElementById('generateBtn');
        btn.textContent = 'Сгенерировать';
        btn.onclick = handleGenerate;

        hideStatus();
    }

    function setMode(mode) {
        currentMode = mode;
        document.querySelectorAll('.mode-btn').forEach(function (btn) {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });

        const ipSelect = document.getElementById('ipRangeSelect');
        if (mode === 'ip') {
            ipSelect.classList.remove('hidden');
        } else {
            ipSelect.classList.add('hidden');
            ipSelect.value = '';
        }

        resetGeneration();
    }

    function downloadFile(name, base64) {
        const link = document.createElement('a');
        link.href = 'data:application/octet-stream;base64,' + base64;
        link.download = name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    /* ---------- I1 via quic.js ---------- */

    async function generateI1(sni, level) {
        const dcid = new Uint8Array(1);
        window.crypto.getRandomValues(dcid);
        const scid = new Uint8Array(0);
        const token = new Uint8Array(0);
        const pkn = new Uint8Array([0]);

        const clientHello = quicTlsClientHelloSniOnly(sni);
        const frames = quicTlsClientHelloToFrames(clientHello, level);
        const payload = frames[0];
        const cutSettings = frames[1];

        const packet = await quicInitial(dcid, scid, token, pkn, payload, 0);

        quicFixCutSettings(
            cutSettings,
            packet.byteLength,
            pkn.byteLength,
            payload.byteLength
        );

        return quicToAWG(packet, cutSettings);
    }

    /* ---------- main flow ---------- */

    async function handleGenerate() {
        if (isGenerating) return;
        isGenerating = true;

        const btn = document.getElementById('generateBtn');
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Генерация...';

        try {
            const rawDomain = document.getElementById('domain').value;
            let domain = cleanDomain(rawDomain) || 'www.cloudflare.com';

            if (domain !== 'www.cloudflare.com') {
                const checkRes = await fetch('/api/check-domain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                const checkData = await checkRes.json();
                if (!checkData.valid) {
                    setStatus(
                        'Домен "' + domain + '" не найден.\nИспользуется www.cloudflare.com',
                        true
                    );
                    domain = 'www.cloudflare.com';
                }
            }

            const level = parseInt(
                document.getElementById('quicLevel').value,
                10
            );

            const i1 = await generateI1(domain, level);

            const ipRangeBase =
                currentMode === 'ip'
                    ? (document.getElementById('ipRangeSelect').value || null)
                    : null;

            const genRes = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domain: domain,
                    mode: currentMode,
                    ipRangeBase: ipRangeBase,
                    i1: i1
                })
            });
            const genData = await genRes.json();

            if (!genData.success) {
                throw new Error(genData.message || 'Ошибка генерации');
            }

            const randomNum = Math.floor(Math.random() * (99 - 10 + 1)) + 10;
            const fileName = 'WARP_' + randomNum + '.conf';
            generatedFileName = fileName;
            generatedFileContent = genData.content;

            downloadFile(fileName, genData.content);

            btn.textContent = fileName;
            btn.onclick = function () {
                downloadFile(generatedFileName, generatedFileContent);
            };

            setStatus('Успешно: ' + fileName, false);
        } catch (err) {
            console.error(err);
            setStatus(
                'Ошибка: ' + (err.message || 'не удалось сгенерировать конфиг'),
                true
            );
            btn.textContent = originalText;
            btn.onclick = handleGenerate;
        } finally {
            isGenerating = false;
            btn.disabled = false;
        }
    }

    /* ---------- wiring ---------- */

    document.addEventListener('DOMContentLoaded', function () {
        const domainInput = document.getElementById('domain');
        const clearBtn = document.getElementById('clearBtn');
        const quicLevel = document.getElementById('quicLevel');
        const ipRange = document.getElementById('ipRangeSelect');
        const generateBtn = document.getElementById('generateBtn');

        generateBtn.onclick = handleGenerate;

        document.querySelectorAll('.mode-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                setMode(btn.dataset.mode);
            });
        });

        domainInput.addEventListener('paste', function (e) {
            e.preventDefault();
            const text =
                (e.clipboardData || window.clipboardData).getData('text');
            domainInput.value = cleanDomain(text);
            resetGeneration();
        });

        domainInput.addEventListener('input', function () {
            resetGeneration();
        });

        clearBtn.addEventListener('click', function () {
            domainInput.value = '';
            resetGeneration();
            domainInput.focus();
        });

        quicLevel.addEventListener('change', function () {
            resetGeneration();
        });

        ipRange.addEventListener('change', function () {
            resetGeneration();
        });
    });
})();