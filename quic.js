const crypto = require('crypto');

const QUIC_SALT = Buffer.from([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
]);

function str8(data) {
    if (data == null) return Buffer.alloc(1);
    const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    const result = Buffer.alloc(input.length + 1);
    result.writeUInt8(input.length, 0);
    input.copy(result, 1);
    return result;
}

function str16(data) {
    if (data == null) return Buffer.alloc(2);
    const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    const result = Buffer.alloc(input.length + 2);
    result.writeUInt16BE(input.length, 0);
    input.copy(result, 2);
    return result;
}

function varint(x) {
    if (x < 0x40) return Buffer.from([x]);
    if (x < 0x4000) {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(x, 0);
        b[0] |= 0x40;
        return b;
    }
    if (x < 0x40000000) {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(x, 0);
        b[0] |= 0x80;
        return b;
    }
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(x), 0);
    b[0] |= 0xC0;
    return b;
}

function varintLength(x) {
    if (x < 0x40) return 1;
    if (x < 0x4000) return 2;
    if (x < 0x40000000) return 4;
    return 8;
}

function concat(buffers, before = 0, after = 0) {
    const bufs = buffers.map(b => (Buffer.isBuffer(b) ? b : Buffer.from(b)));
    const total = bufs.reduce((a, b) => a + b.length, before + after);
    const result = Buffer.alloc(total);
    let offset = before;
    for (const b of bufs) {
        b.copy(result, offset);
        offset += b.length;
    }
    return result;
}

function xorBuffer(dst, src, dstOffset, srcOffset, length) {
    for (let i = 0; i < length; i++) {
        dst[dstOffset + i] ^= src[srcOffset + i];
    }
}

function deriveSecret(key, length, label, context = '') {
    const data = concat([
        str8('tls13 ' + label),
        str8(context),
        Buffer.from([0x01]),
    ], 2);
    data.writeUInt16BE(length, 0);
    const h = crypto.createHmac('sha256', key).update(data).digest();
    return Buffer.from(h.subarray(0, length));
}

function encryptPayload(key, payload, iv, aad) {
    const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
    cipher.setAAD(aad);
    const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([enc, tag]);
}

function deriveHpMask(key, sample) {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(sample), cipher.final()]);
}

function measureLengths(dcidLength, scidLength, tokenLength, pknLength, payloadLength, padto = 0) {
    const baseHeaderLength = 8 + dcidLength + scidLength + tokenLength + pknLength;
    const tagLength = 16;
    let paddingLength = 0;

    const getLengthByteSize = () => varintLength(pknLength + payloadLength + paddingLength + tagLength);
    const getOverallLength = () => baseHeaderLength + getLengthByteSize() + payloadLength + paddingLength + tagLength;

    let overallLength = getOverallLength();
    if (overallLength < padto) {
        paddingLength = padto - overallLength;
        while (paddingLength && getOverallLength() > padto) paddingLength--;
        if (getOverallLength() < padto) paddingLength++;
        overallLength = getOverallLength();
    }
    if (pknLength + payloadLength + paddingLength + tagLength < 20) {
        paddingLength = 20 - pknLength - payloadLength - tagLength;
        overallLength = getOverallLength();
    }
    const headerLength = baseHeaderLength + getLengthByteSize();

    return { total: overallLength, header: headerLength, padding: paddingLength };
}

async function quicInitial(dcid, scid, token, pkn, payload, padto) {
    const lengths = measureLengths(dcid.length, scid.length, token.length, pkn.length, payload.length, padto);

    const header = concat([
        Buffer.from([0xc0 | (pkn.length - 1), 0, 0, 0, 1]),
        str8(dcid),
        str8(scid),
        str8(token),
        varint(pkn.length + payload.length + lengths.padding + 16),
        pkn,
    ]);

    const initSecret = crypto.createHmac('sha256', QUIC_SALT).update(dcid).digest();
    const clientSecret = deriveSecret(initSecret, 32, 'client in');
    const quicKey = deriveSecret(clientSecret, 16, 'quic key');
    const quicIv = deriveSecret(clientSecret, 12, 'quic iv');
    const quicHp = deriveSecret(clientSecret, 16, 'quic hp');

    xorBuffer(quicIv, pkn, 12 - pkn.length, 0, pkn.length);

    const paddedPayload = concat([payload], 0, lengths.padding);
    const encryptedPayload = encryptPayload(quicKey, paddedPayload, quicIv, header);

    const sample = encryptedPayload.subarray(4 - pkn.length, 20 - pkn.length);
    const mask = deriveHpMask(quicHp, sample);
    mask[0] &= 0x0f;
    xorBuffer(header, mask, 0, 0, 1);
    xorBuffer(header, mask, header.length - pkn.length, 1, pkn.length);

    return concat([header, encryptedPayload]);
}

function cryptoFrame(data, offset = 0) {
    return concat([Buffer.from([0x06]), varint(offset), varint(data.length), data]);
}

function tlsExt(code, content) {
    const result = concat([content], 4);
    result.writeUInt16BE(code, 0);
    result.writeUInt16BE(content.length, 2);
    return result;
}

function tlsExtSni(sni) {
    const sniBuffer = str16(sni);
    const extBuffer = concat([sniBuffer], 3);
    extBuffer.writeUInt16BE(sniBuffer.length + 1, 0);
    extBuffer.writeUInt8(0, 2);
    return tlsExt(0, extBuffer);
}

function tlsClientHelloSniOnly(sni) {
    const randomBytes = crypto.randomBytes(32);
    const payload = concat([
        Buffer.from([0x03, 0x03]),
        randomBytes,
        Buffer.from([0, 0, 0, 0]),
        str16(tlsExtSni(sni)),
    ], 4);
    payload.writeUInt32BE(payload.length - 4, 0);
    payload.writeUInt8(0x01, 0);
    return payload;
}

function tlsClientHelloToFrames(clientHello, level = 4) {
    let payload;
    let cutSettings;
    if (!level) {
        payload = cryptoFrame(clientHello);
        const dataOffset = payload.length - clientHello.length;
        cutSettings = [dataOffset + 6, 32, clientHello.length - 38, 16];
    } else {
        const cutPresets = {
            1: [38, Infinity, 0, 38, 32, false],
            2: [38, Infinity, 0, 38, 37, false],
            3: [0, 1, 38, Infinity, 0, false],
            4: [0, 1, 38, Infinity, 0, true],
        };
        let [p1s, p1e, p2s, p2e, dropTail, skipZeroes] = cutPresets[level];
        if (skipZeroes) {
            while (clientHello[p2s] === 0) p2s++;
        }
        payload = concat([
            cryptoFrame(clientHello.subarray(p1s, p1e), p1s),
            cryptoFrame(clientHello.subarray(p2s, p2e), p2s),
        ]);
        cutSettings = [payload.length - dropTail, 16 + dropTail];
    }
    return [payload, cutSettings];
}

function fixCutSettings(cutSettings, packetLength, pknLength, payloadLength) {
    if (cutSettings[0] < 20 - pknLength) {
        const toAdd = 20 - pknLength - cutSettings[0];
        cutSettings[0] += toAdd;
        cutSettings[1] -= toAdd;
    }
    cutSettings[0] += packetLength - payloadLength - 16;
}

function toAWG(buffer, parts = null, includeFirst = true) {
    let include = includeFirst;
    let offset = 0;
    let result = '';
    if (!parts) return `<b 0x${buffer.toString('hex')}>`;
    for (const part of parts) {
        if (part > 0) {
            if (include) {
                result += `<b 0x${buffer.subarray(offset, offset + part).toString('hex')}>`;
            } else {
                result += `<r ${part}>`;
            }
            offset += part;
        }
        include = !include;
    }
    return result;
}

/**
 * Generate I1 value for AmneziaWG (default: +++ Cut Zeroes, level 4)
 * @param {string} domain SNI
 * @param {number} level 0..4
 */
async function generateI1(domain = 'www.google.com', level = 4) {
    const dcid = crypto.randomBytes(1);
    const scid = Buffer.alloc(0);
    const token = Buffer.alloc(0);
    const pkn = Buffer.from([0]);
    const clientHello = tlsClientHelloSniOnly(domain);
    const [payload, cutSettings] = tlsClientHelloToFrames(clientHello, level);
    const packet = await quicInitial(dcid, scid, token, pkn, payload, 0);
    fixCutSettings(cutSettings, packet.length, pkn.length, payload.length);
    return toAWG(packet, cutSettings);
}

module.exports = { generateI1 };