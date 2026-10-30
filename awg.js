const fetch = require('node-fetch');
const nacl = require('tweetnacl');
const { Buffer } = require('buffer');

const PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
    1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
    4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
    8854, 8886
];

const IP_BASES = [
    '8.6.112.0', '8.34.70.0', '8.34.146.0', '8.35.211.0',
    '8.39.125.0', '8.39.204.0', '8.39.214.0', '8.47.69.0',
    '188.114.96.0', '188.114.97.0', '188.114.98.0', '188.114.99.0',
    '162.159.192.0', '162.159.195.0'
];

const DOMAIN_POINT = 'engage.cloudflareclient.com';

function randomFrom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randomIP(base) {
    const parts = base.split('.');
    parts[3] = String(Math.floor(Math.random() * 254) + 1);
    return parts.join('.');
}

function buildEndpoint(mode, ipRangeBase) {
    const port = randomFrom(PORTS);
    let host;

    if (mode === 'domain') {
        host = DOMAIN_POINT;
    } else if (mode === 'ip') {
        const base = ipRangeBase || randomFrom(IP_BASES);
        host = randomIP(base);
    } else {
        // auto: mix of all IP ranges + domain point
        const pool = IP_BASES.concat([DOMAIN_POINT]);
        const base = randomFrom(pool);
        host = base === DOMAIN_POINT ? DOMAIN_POINT : randomIP(base);
    }

    return `${host}:${port}`;
}

function generateKeys() {
    const keyPair = nacl.box.keyPair();
    return {
        privKey: Buffer.from(keyPair.secretKey).toString('base64'),
        pubKey: Buffer.from(keyPair.publicKey).toString('base64')
    };
}

async function apiRequest(method, endpoint, body = null, token = null) {
    const headers = {
        'User-Agent': 'okhttp/3.12.1',
        'Content-Type': 'application/json'
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(
        `https://api.devices.cloudflare.com/v0/${endpoint}`,
        options
    );
    return response.json();
}

async function generateWarpConfig({ mode, ipRangeBase, i1 }) {
    const { privKey, pubKey } = generateKeys();

    const regResponse = await apiRequest('POST', 'reg', {
        install_id: '',
        tos: new Date().toISOString(),
        key: pubKey,
        fcm_token: '',
        type: 'ios',
        locale: 'en_US'
    });

    const id = regResponse.result.id;
    const token = regResponse.result.token;

    const warpResponse = await apiRequest(
        'PATCH',
        `reg/${id}`,
        { warp_enabled: true },
        token
    );

    const peerPub = warpResponse.result.config.peers[0].public_key;
    const clientIPv4 = warpResponse.result.config.interface.addresses.v4;
    const clientIPv6 = warpResponse.result.config.interface.addresses.v6;

    const endpoint = buildEndpoint(mode, ipRangeBase);

    const conf = `[Interface]
PrivateKey = ${privKey}
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = ${i1}
Address = ${clientIPv4}, ${clientIPv6}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = ${peerPub}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}
PersistentKeepalive = 25`;

    return conf;
}

async function validateDomain(domain) {
    const fallback = 'www.cloudflare.com';
    if (!domain) return { valid: false, domain: fallback };

    for (const type of ['A', 'AAAA']) {
        try {
            const res = await fetch(
                `https://dns.cloudflare.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
                { headers: { Accept: 'application/dns-json' } }
            );
            const data = await res.json();
            if (Array.isArray(data.Answer) && data.Answer.length > 0) {
                return { valid: true, domain };
            }
        } catch (_) {
            /* ignore and try next record type */
        }
    }

    return { valid: false, domain: fallback };
}

module.exports = { generateWarpConfig, validateDomain };