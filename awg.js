const fetch = require('node-fetch');
const nacl = require('tweetnacl');
const { generateI1 } = require('./quic');

const API_BASE = 'https://api.devices.cloudflare.com/v0i1909051800';

const PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943,
    945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
    1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500,
    5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
];

const IP_RANGES = [
    '8.6.112', '8.34.70', '8.34.146', '8.35.211', '8.39.125', '8.39.204',
    '8.39.214', '8.47.69', '188.114.96', '188.114.97', '188.114.98', '188.114.99',
    '162.159.192', '162.159.195',
];

function randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randomIpFromRange(range) {
    const last = Math.floor(Math.random() * 256);
    return `${range}.${last}`;
}

function generateEndpoint(mode, ipRange) {
    const port = randomChoice(PORTS);
    let host;

    if (mode === 'domain') {
        host = 'engage.cloudflareclient.com';
    } else if (mode === 'ip') {
        const range = ipRange && IP_RANGES.includes(ipRange) ? ipRange : randomChoice(IP_RANGES);
        host = randomIpFromRange(range);
    } else {
        // auto — mix of both
        if (Math.random() < 0.01) {
            host = 'engage.cloudflareclient.com';
        } else {
            host = randomIpFromRange(randomChoice(IP_RANGES));
        }
    }

    return `${host}:${port}`;
}

function generateKeys() {
    const keyPair = nacl.box.keyPair();
    return {
        privKey: Buffer.from(keyPair.secretKey).toString('base64'),
        pubKey: Buffer.from(keyPair.publicKey).toString('base64'),
    };
}

async function apiRequest(method, endpoint, body = null, token = null) {
    const headers = {
        'User-Agent': '',
        'Content-Type': 'application/json',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(`${API_BASE}/${endpoint}`, options);
    return response.json();
}

async function generateWarpConfig({
    mode = 'auto',
    ipRange = null,
    domain = 'www.google.com',
    level = 4,
} = {}) {
    const { privKey, pubKey } = generateKeys();

    const regBody = {
        install_id: '',
        tos: new Date().toISOString(),
        key: pubKey,
        fcm_token: '',
        type: 'ios',
        locale: 'en_US',
    };
    const regResponse = await apiRequest('POST', 'reg', regBody);
    if (!regResponse || !regResponse.result) {
        throw new Error('Failed to register with Cloudflare WARP');
    }
    const id = regResponse.result.id;
    const token = regResponse.result.token;

    const warpResponse = await apiRequest('PATCH', `reg/${id}`, { warp_enabled: true }, token);
    const peer_pub = warpResponse.result.config.peers[0].public_key;
    const client_ipv4 = warpResponse.result.config.interface.addresses.v4;
    const client_ipv6 = warpResponse.result.config.interface.addresses.v6;

    const i1 = await generateI1(domain, level);
    const endpoint = generateEndpoint(mode, ipRange);

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
Address = ${client_ipv4}, ${client_ipv6}
DNS = 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844
MTU = 1280

[Peer]
PublicKey = ${peer_pub}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}
PersistentKeepalive = 25`;

    return conf;
}

module.exports = { generateWarpConfig, IP_RANGES };