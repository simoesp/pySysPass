import api from '@/api/axios'

let _cachedKey = null

async function fetchPublicKey() {
  if (_cachedKey) return _cachedKey

  const r = await api.get('/security/public-key')
  const pem = r.data.public_key
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '')

  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0))

  _cachedKey = await window.crypto.subtle.importKey(
    'spki',
    der.buffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  )
  return _cachedKey
}

/**
 * Encrypt a password with the server's RSA public key.
 * Returns "RSA:<base64>" which the server transparently decrypts.
 * Falls back to plaintext if Web Crypto or the server is unavailable.
 */
export async function encryptPassword(plaintext) {
  if (!plaintext) return plaintext
  try {
    const key = await fetchPublicKey()
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      key,
      new TextEncoder().encode(plaintext),
    )
    const b64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    return `RSA:${b64}`
  } catch {
    // Graceful fallback — still works on HTTPS or in environments without Web Crypto
    return plaintext
  }
}

/** Pre-warm the key cache (call on app start or login page mount). */
export function preloadEncryptionKey() {
  fetchPublicKey().catch(() => {})
}
