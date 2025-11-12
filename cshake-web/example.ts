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
console.log(encodeHex(Custom.new("test", "test").once_to_bytes(encodeText("Hello, World!"), 32)));
