const textEncoder = new TextEncoder();
// const textDecoder = new TextDecoder();

const encodeText = (input: string) => textEncoder.encode(input);
// const decodeText = (input: Uint8Array) => textDecoder.decode(input);

function encodeHex(buffer: Uint8Array): string {
    return Array.from(buffer).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// cargo build -p cshake-web --target wasm32-unknown-unknown --release
// wasm-bindgen --target deno --out-dir path/to/dist path/to/target/wasm32-unknown-unknown/release/cshake_web.wasm
// @deno-types="./cshake_web.d.ts"
import { Custom } from "./cshake_web.js";

console.log(encodeHex(Custom.shake().once_to_bytes(encodeText("Hello, World!"), 32)));
console.log(encodeHex(Custom.from_string("test", "test").once_to_bytes(encodeText("Hello, World!"), 32)));

{
    const array = new Uint8Array([1, 2, 3, 4]);
    Custom.shake().create().chain_absorb(encodeText("Hello, World!")).squeeze_xor(array);
    console.log(encodeHex(array))
}

{
    const array = new Uint8Array([1, 2, 3, 4]);
    Custom.shake().create().chain_absorb(encodeText("Hello, World!1")).squeeze_xor(array);
    console.log(encodeHex(array))
}
