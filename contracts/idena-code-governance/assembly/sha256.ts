const K: u32[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

export function sha256(input: Uint8Array): Uint8Array {
  const blocks = (input.length + 9 + 63) / 64;
  const padded = new Uint8Array(blocks * 64);
  memory.copy(padded.dataStart, input.dataStart, input.length);
  padded[input.length] = 0x80;
  const bitLength = <u64>input.length * 8;
  for (let i = 0; i < 8; i++) {
    padded[padded.length - 1 - i] = <u8>(bitLength >> (<u64>i * 8));
  }

  let h0: u32 = 0x6a09e667;
  let h1: u32 = 0xbb67ae85;
  let h2: u32 = 0x3c6ef372;
  let h3: u32 = 0xa54ff53a;
  let h4: u32 = 0x510e527f;
  let h5: u32 = 0x9b05688c;
  let h6: u32 = 0x1f83d9ab;
  let h7: u32 = 0x5be0cd19;
  const words = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const p = offset + i * 4;
      words[i] =
        (<u32>padded[p] << 24)
        | (<u32>padded[p + 1] << 16)
        | (<u32>padded[p + 2] << 8)
        | <u32>padded[p + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotateRight(words[i - 15], 7) ^ rotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3);
      const s1 = rotateRight(words[i - 2], 17) ^ rotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10);
      words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;
    for (let i = 0; i < 64; i++) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = h + sum1 + choice + K[i] + words[i];
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  const output = new Uint8Array(32);
  writeU32BE(output, 0, h0);
  writeU32BE(output, 4, h1);
  writeU32BE(output, 8, h2);
  writeU32BE(output, 12, h3);
  writeU32BE(output, 16, h4);
  writeU32BE(output, 20, h5);
  writeU32BE(output, 24, h6);
  writeU32BE(output, 28, h7);
  return output;
}

function rotateRight(value: u32, count: i32): u32 {
  return (value >> count) | (value << (32 - count));
}

function writeU32BE(output: Uint8Array, offset: i32, value: u32): void {
  output[offset] = <u8>(value >> 24);
  output[offset + 1] = <u8>(value >> 16);
  output[offset + 2] = <u8>(value >> 8);
  output[offset + 3] = <u8>value;
}
