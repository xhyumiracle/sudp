/**
 * SHA-256 over a byte buffer. Thin wrapper over the platform's WebCrypto.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // `crypto.subtle` is available in modern browsers and Node >= 20.
  const buf = await crypto.subtle.digest("SHA-256", data as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}
