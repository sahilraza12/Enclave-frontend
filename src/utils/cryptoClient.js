// client/src/utils/cryptoClient.js

// -------------------------------------------------------------
// 1. Storage & In-Memory Key Cache
// -------------------------------------------------------------
let cachedStaticKey = null;
let cachedAuditKey = null;

// Safe fallback agar .env load na ho sake
const FALLBACK_STATIC_HEX = 'e2b7a9f4c3d1e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3';
const RAW_KEY_HEX = import.meta.env.VITE_CRYPTO_SECRET_KEY || FALLBACK_STATIC_HEX;

// -------------------------------------------------------------
// 2. Binary & Hex Serialization Helpers
// -------------------------------------------------------------
export function hexToBuffer(hex) {
  if (!hex || typeof hex !== 'string') return new ArrayBuffer(0);
  const cleanHex = hex.trim();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

export function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// -------------------------------------------------------------
// 3. Dynamic Asymmetric ECDH Key Exchange (P-256)
// -------------------------------------------------------------

export async function generateUserKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, 
    ['deriveKey', 'deriveBits']
  );
}

export async function exportPublicKey(cryptoKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return JSON.stringify(exported);
}

export async function exportPrivateKey(cryptoKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return JSON.stringify(exported);
}

export async function importPublicKey(jwkString) {
  const jwk = typeof jwkString === 'string' ? JSON.parse(jwkString) : jwkString;
  const { d, ...cleanJwk } = jwk;
  return await window.crypto.subtle.importKey(
    'jwk',
    { ...cleanJwk, key_ops: [] },
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

export async function importPrivateKey(jwkString) {
  const jwk = typeof jwkString === 'string' ? JSON.parse(jwkString) : jwkString;
  return await window.crypto.subtle.importKey(
    'jwk',
    { ...jwk, key_ops: ['deriveKey', 'deriveBits'] },
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
}

export async function importPublicKeyFromPrivateJwk(jwkString) {
  const privateJwk = typeof jwkString === 'string' ? JSON.parse(jwkString) : jwkString;
  const { d, key_ops, ...publicJwk } = privateJwk;
  return importPublicKey(publicJwk);
}

export async function deriveSharedSecret(myPrivateKey, theirPublicKey) {
  return await window.crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: theirPublicKey
    },
    myPrivateKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptRawBuffer(bufferData, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextWithTag = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    bufferData
  );

  const tagLength = 16;
  const ciphertextLength = ciphertextWithTag.byteLength - tagLength;

  return {
    encryptedText: bufferToHex(ciphertextWithTag.slice(0, ciphertextLength)),
    iv: bufferToHex(iv.buffer),
    authTag: bufferToHex(ciphertextWithTag.slice(ciphertextLength))
  };
}

async function decryptRawBuffer(encryptedHex, ivHex, authTagHex, key) {
  const ciphertext = new Uint8Array(hexToBuffer(encryptedHex));
  const authTag = new Uint8Array(hexToBuffer(authTagHex));
  const iv = new Uint8Array(hexToBuffer(ivHex));

  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.length);

  return await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    combined.buffer
  );
}

export async function encryptWithDerivedKey(plainText, sharedKey) {
  try {
    const encoded = new TextEncoder().encode(plainText);
    return await encryptRawBuffer(encoded, sharedKey);
  } catch (err) {
    console.error('Derived key encryption failed:', err);
    throw err;
  }
}

export async function decryptWithDerivedKey(encryptedHex, ivHex, authTagHex, sharedKey) {
  try {
    if (!encryptedHex || !ivHex || !authTagHex) return encryptedHex || '';
    if (!sharedKey) return '[Waiting for Encryption Keys...]';

    const decryptedBuffer = await decryptRawBuffer(encryptedHex, ivHex, authTagHex, sharedKey);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    return '[Decryption Failed: Mismatched Key]';
  }
}

// -------------------------------------------------------------
// 4. Per-Message Session Keys & Dual-Envelope Wrapping
// -------------------------------------------------------------
export async function generateSessionKey() {
  return await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, 
    ['encrypt', 'decrypt']
  );
}

export async function encryptWithSessionKey(plainText, sessionKey) {
  const encoded = new TextEncoder().encode(plainText);
  return await encryptRawBuffer(encoded, sessionKey);
}

export async function decryptWithSessionKey(encryptedHex, ivHex, authTagHex, sessionKey) {
  try {
    const decryptedBuffer = await decryptRawBuffer(encryptedHex, ivHex, authTagHex, sessionKey);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    return '[Decryption Failed: Mismatched Key]';
  }
}

export async function encryptAudioBlob(audioBlob, sessionKey) {
  const encrypted = await encryptRawBuffer(await audioBlob.arrayBuffer(), sessionKey);
  return {
    encryptedBlob: new Blob([hexToBuffer(encrypted.encryptedText)], { type: 'application/octet-stream' }),
    iv: encrypted.iv,
    authTag: encrypted.authTag
  };
}

export async function decryptAudioBytes(encryptedBytes, ivHex, authTagHex, sessionKey) {
  const encryptedHex = bufferToHex(encryptedBytes);
  const decryptedBuffer = await decryptRawBuffer(encryptedHex, ivHex, authTagHex, sessionKey);
  return URL.createObjectURL(new Blob([decryptedBuffer], { type: 'audio/webm' }));
}

export async function wrapKeyForUser(sessionKey, myPrivateKey, theirPublicKey) {
  try {
    const sharedKey = await deriveSharedSecret(myPrivateKey, theirPublicKey);
    const rawSessionKey = await window.crypto.subtle.exportKey('raw', sessionKey);
    
    const wrappedPayload = await encryptRawBuffer(rawSessionKey, sharedKey);
    return JSON.stringify(wrappedPayload);
  } catch (err) {
    console.error('wrapKeyForUser failed:', err);
    return null;
  }
}

export async function unwrapKeyForUser(wrappedKey, sharedKey) {
  try {
    if (!wrappedKey || !sharedKey) return null;
    const envelope = typeof wrappedKey === 'string' ? JSON.parse(wrappedKey) : wrappedKey;
    
    if (!envelope.encryptedText || !envelope.iv || !envelope.authTag) {
      return null;
    }

    const rawKeyBuffer = await decryptRawBuffer(
      envelope.encryptedText,
      envelope.iv,
      envelope.authTag,
      sharedKey
    );

    return await window.crypto.subtle.importKey(
      'raw',
      rawKeyBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  } catch (err) {
    console.warn('unwrapKeyForUser failed:', err);
    return null;
  }
}

// -------------------------------------------------------------
// 5. Static Shared Key Fallback (With Guaranteed Hex Fallback)
// -------------------------------------------------------------
async function getStaticKey() {
  if (cachedStaticKey) return cachedStaticKey;

  const hexKeyToUse = (RAW_KEY_HEX && RAW_KEY_HEX.trim().length === 64) 
    ? RAW_KEY_HEX.trim() 
    : FALLBACK_STATIC_HEX;

  const keyBuffer = hexToBuffer(hexKeyToUse);
  cachedStaticKey = await window.crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  return cachedStaticKey;
}

export async function encryptClient(plainText) {
  try {
    const key = await getStaticKey();
    if (!key) throw new Error('Static encryption key unavailable');

    const encoded = new TextEncoder().encode(plainText);
    return await encryptRawBuffer(encoded, key);
  } catch (err) {
    console.error('Client encryption failed:', err);
    throw err;
  }
}

export async function decryptClient(encryptedTextHex, ivHex, authTagHex) {
  try {
    if (!encryptedTextHex || !ivHex || !authTagHex) return encryptedTextHex || '';

    const key = await getStaticKey();
    if (!key) return '[Decryption Unavailable]';

    const decryptedBuffer = await decryptRawBuffer(encryptedTextHex, ivHex, authTagHex, key);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    return '[Decryption Failed]';
  }
}

// -------------------------------------------------------------
// 6. Universal Enterprise Master Audit (Fixed for missing DB tag)
// -------------------------------------------------------------
const AUDIT_VAULT_PASSPHRASE = 'Char_Enterprise_Master_Audit_Key_2026';

async function getMasterAuditKey() {
  if (cachedAuditKey) return cachedAuditKey;
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(AUDIT_VAULT_PASSPHRASE),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  cachedAuditKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('audit_salt_fixed_char_vault_2026'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return cachedAuditKey;
}

export async function encryptMasterAudit(plainText) {
  try {
    const key = await getMasterAuditKey();
    const enc = new TextEncoder();
    const rawData = await encryptRawBuffer(enc.encode(plainText), key);
    
    // TRICK: Combine encryptedText and authTag into a single string
    // Kyunki DB me alag se auditAuthTag field nahi hai
    return {
      encryptedText: rawData.encryptedText + rawData.authTag,
      iv: rawData.iv
    };
  } catch (err) {
    console.warn('Master audit wrap failed:', err);
    return null;
  }
}

export async function decryptMasterAudit(combinedHex, ivHex) {
  try {
    if (!combinedHex || !ivHex) return null;
    const key = await getMasterAuditKey();

    // Extract authTag (last 32 hex characters = 16 bytes)
    const authTagHex = combinedHex.slice(-32);
    const encryptedTextHex = combinedHex.slice(0, -32);

    const decryptedBuffer = await decryptRawBuffer(encryptedTextHex, ivHex, authTagHex, key);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    return null;
  }
}