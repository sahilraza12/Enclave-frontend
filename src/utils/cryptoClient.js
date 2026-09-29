// client/src/utils/cryptoClient.js

// -------------------------------------------------------------
// 1. Storage & In-Memory Key Cache
// -------------------------------------------------------------
let cachedStaticKey = null;
const RAW_KEY_HEX = import.meta.env.VITE_CRYPTO_SECRET_KEY;

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

/**
 * Generate a unique ECDH keypair in the browser
 */
export async function generateUserKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Export Public Key as a JWK JSON string
 */
export async function exportPublicKey(cryptoKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return JSON.stringify(exported);
}

/**
 * Export Private Key as a JWK JSON string
 */
export async function exportPrivateKey(cryptoKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return JSON.stringify(exported);
}

/**
 * Import a JWK JSON string as an ECDH Public Key
 */
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

/**
 * Import a stored JWK JSON string as an ECDH Private Key
 */
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

/**
 * Compute shared AES-256-GCM symmetric key using ECDH
 * (My Private Key + Partner's Public Key)
 */
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

/**
 * Encrypt arbitrary Uint8Array or ArrayBuffer with AES-GCM
 */
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

/**
 * Decrypt to raw ArrayBuffer using AES-GCM
 */
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

/**
 * Encrypt message string with dynamically derived AES-GCM shared key
 */
export async function encryptWithDerivedKey(plainText, sharedKey) {
  try {
    const encoded = new TextEncoder().encode(plainText);
    return await encryptRawBuffer(encoded, sharedKey);
  } catch (err) {
    console.error('Derived key encryption failed:', err);
    throw err;
  }
}

/**
 * Decrypt message with dynamically derived AES-GCM shared key
 */
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
// 4. Per-Message Session Keys & Dual-Envelope Wrapping (Option A)
// -------------------------------------------------------------
export async function generateSessionKey() {
  return await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // Must be extractable so it can be wrapped
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

/**
 * Wrap raw session key using ECDH shared key derived on the fly
 */
export async function wrapKeyForUser(sessionKey, myPrivateKey, theirPublicKey) {
  try {
    const sharedKey = await deriveSharedSecret(myPrivateKey, theirPublicKey);
    const rawSessionKey = await window.crypto.subtle.exportKey('raw', sessionKey);
    
    // Encrypt raw session key bytes directly (no double text encoding)
    const wrappedPayload = await encryptRawBuffer(rawSessionKey, sharedKey);
    return JSON.stringify(wrappedPayload);
  } catch (err) {
    console.error('wrapKeyForUser failed:', err);
    return null;
  }
}

/**
 * Unwrap session key using the receiver's private key + sender's public key (or derived shared key)
 */
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
// 5. Static Shared Key Fallback (Legacy/Temporary Support)
// -------------------------------------------------------------
async function getStaticKey() {
  if (cachedStaticKey) return cachedStaticKey;

  if (!RAW_KEY_HEX || RAW_KEY_HEX.length !== 64) {
    console.warn('VITE_CRYPTO_SECRET_KEY not found or invalid; static mode unavailable');
    return null;
  }

  const keyBuffer = hexToBuffer(RAW_KEY_HEX);
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