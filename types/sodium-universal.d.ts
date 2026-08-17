declare module 'sodium-universal' {
  import sodium from 'sodium-native'

  // sodium-universal resolves to sodium-native on Node and sodium-javascript
  // elsewhere, but only the former ships types, so we borrow them. They narrow
  // every byte parameter to Buffer, which libsodium does not require: any
  // Uint8Array works, for destinations as well as inputs.
  //
  // Rewritten wholesale rather than per-method, so this keeps describing
  // sodium-native rather than whichever subset of it we happen to call.

  type WidenBytes<T> = T extends Buffer
    ? Uint8Array
    : T extends Buffer[]
      ? Uint8Array[]
      : T

  type WidenParams<A extends readonly unknown[]> = {
    [K in keyof A]: WidenBytes<A[K]>
  }

  // Return types are left alone: those are values sodium-native hands back,
  // and on Node they really are Buffers.
  type WidenFn<F> = F extends (...args: infer A) => infer R
    ? (...args: WidenParams<A>) => R
    : F

  const widened: { [K in keyof typeof sodium]: WidenFn<(typeof sodium)[K]> }
  export = widened
}
