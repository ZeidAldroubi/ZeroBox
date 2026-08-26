/// <reference types="vite/client" />
declare module 'argon2-browser' {
  const argon2: { ArgonType: { Argon2id: number }; hash(options: { pass: string; salt: Uint8Array; time: number; mem: number; hashLen: number; parallelism: number; type: number }): Promise<{ hash: Uint8Array }> }
  export default argon2
}
declare module 'argon2-browser/dist/argon2-bundled.min.js' {
  const argon2: { ArgonType: { Argon2id: number }; hash(options: { pass: string; salt: Uint8Array; time: number; mem: number; hashLen: number; parallelism: number; type: number }): Promise<{ hash: Uint8Array }> }
  export default argon2
}
