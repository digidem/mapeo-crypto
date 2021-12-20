declare module 'base32.js' {
  type EncodingType = 'crockford' | 'rfc4648'
  interface EncoderOptions {
    /** Supported Base-32 variants are "rfc4648" and "crockford" (defaults to "rfc4648") */
    type?: EncodingType
    /** Convert output to lower case (defaults to false) */
    lc?: boolean
  }
  interface DecoderOptions {
    /** Supported Base-32 variants are "rfc4648" and "crockford" */
    type?: EncodingType
  }

  interface Base32 {
    encode(input: Buffer, options?: EncoderOptions): string
    decode(input: string, options?: DecoderOptions): Buffer
  }
  const base32: Base32
  export = base32
}
