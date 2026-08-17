declare module 'sodium-universal' {
  import sodium from 'sodium-native'

  // sodium-universal resolves to sodium-native on Node and sodium-javascript
  // elsewhere, but only the former ships types, so we borrow them. They narrow
  // every parameter to Buffer, which libsodium does not require: any Uint8Array
  // works. Widen the inputs we pass caller-supplied data to, so the Buffer in
  // those signatures does not leak out into this package's public types.
  //
  // Output parameters stay Buffer - we always allocate those ourselves.
  interface WidenedInputs {
    crypto_pwhash(
      output: Buffer,
      password: Uint8Array,
      salt: Uint8Array,
      opslimit: number,
      memlimit: number,
      algorithm: number,
    ): void
    crypto_generichash(
      output: Buffer,
      input: Uint8Array,
      key?: Uint8Array,
    ): void
    crypto_generichash_batch(
      output: Buffer,
      inputArray: Uint8Array[],
      key?: Uint8Array,
    ): void
    crypto_sign_detached(
      signature: Buffer,
      message: Uint8Array,
      secretKey: Uint8Array,
    ): void
    crypto_sign_verify_detached(
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array,
    ): boolean
    crypto_sign_seed_keypair(
      publicKey: Buffer,
      secretKey: Buffer,
      seed: Uint8Array,
    ): void
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext: Buffer,
      message: Uint8Array,
      ad: Uint8Array | null,
      nullValue: null,
      npub: Uint8Array,
      key: Uint8Array,
    ): void
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      message: Buffer,
      nullValue: null,
      ciphertext: Uint8Array,
      ad: Uint8Array | null,
      npub: Uint8Array,
      key: Uint8Array,
    ): void
  }

  const widened: Omit<typeof sodium, keyof WidenedInputs> & WidenedInputs
  export = widened
}
