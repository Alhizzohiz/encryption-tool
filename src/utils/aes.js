/**
 * AES (Advanced Encryption Standard) implementation
 * Supports both 128-bit and 256-bit key sizes
 * 
 * This implementation follows the FIPS 197 specification
 * and includes comprehensive step-by-step visualization
 */

// AES S-Box lookup table for SubBytes operation
const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Inverse S-Box lookup table for InvSubBytes operation
const INV_SBOX = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Rcon lookup table for key expansion
const RCON = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
  0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
];

/**
 * Converts a hexadecimal string to a Uint8Array
 * @param {string} hex - Hexadecimal string
 * @returns {Uint8Array} - Byte array
 */
const hexToBytes = (hex) => {
  // Remove any spaces or non-hex characters
  hex = hex.replace(/[^0-9A-Fa-f]/g, '');
  
  // Ensure even length
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i/2] = parseInt(hex.substr(i, 2), 16);
  }
  
  return bytes;
};

/**
 * Converts a Uint8Array to a hexadecimal string
 * @param {Uint8Array} bytes - Byte array
 * @returns {string} - Hexadecimal string
 */
const bytesToHex = (bytes) => {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Performs the SubBytes operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after SubBytes
 */
const subBytes = (state) => {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = SBOX[state[i]];
  }
  return result;
};

/**
 * Performs the inverse SubBytes operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after InvSubBytes
 */
const invSubBytes = (state) => {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = INV_SBOX[state[i]];
  }
  return result;
};

/**
 * Performs the ShiftRows operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after ShiftRows
 */
const shiftRows = (state) => {
  const result = new Uint8Array(16);
  
  // Row 0: No shift
  result[0] = state[0];
  result[4] = state[4];
  result[8] = state[8];
  result[12] = state[12];
  
  // Row 1: Shift left by 1
  result[1] = state[5];
  result[5] = state[9];
  result[9] = state[13];
  result[13] = state[1];
  
  // Row 2: Shift left by 2
  result[2] = state[10];
  result[6] = state[14];
  result[10] = state[2];
  result[14] = state[6];
  
  // Row 3: Shift left by 3
  result[3] = state[15];
  result[7] = state[3];
  result[11] = state[7];
  result[15] = state[11];
  
  return result;
};

/**
 * Performs the inverse ShiftRows operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after InvShiftRows
 */
const invShiftRows = (state) => {
  const result = new Uint8Array(16);
  
  // Row 0: No shift
  result[0] = state[0];
  result[4] = state[4];
  result[8] = state[8];
  result[12] = state[12];
  
  // Row 1: Shift right by 1
  result[5] = state[1];
  result[9] = state[5];
  result[13] = state[9];
  result[1] = state[13];
  
  // Row 2: Shift right by 2
  result[10] = state[2];
  result[14] = state[6];
  result[2] = state[10];
  result[6] = state[14];
  
  // Row 3: Shift right by 3
  result[15] = state[3];
  result[3] = state[7];
  result[7] = state[11];
  result[11] = state[15];
  
  return result;
};

/**
 * Multiply two bytes in GF(2^8)
 * @param {number} a - First byte
 * @param {number} b - Second byte
 * @returns {number} - Product in GF(2^8)
 */
const galoisMultiply = (a, b) => {
  let p = 0;
  let hiBitSet;
  for (let i = 0; i < 8; i++) {
    if ((b & 1) !== 0) {
      p ^= a;
    }
    hiBitSet = (a & 0x80) !== 0;
    a <<= 1;
    if (hiBitSet) {
      a ^= 0x1b; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
    }
    b >>= 1;
  }
  return p & 0xff;
};

/**
 * Performs the MixColumns operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after MixColumns
 */
const mixColumns = (state) => {
  const result = new Uint8Array(16);
  
  for (let i = 0; i < 4; i++) {
    const col = i * 4;
    result[col] = galoisMultiply(2, state[col]) ^ galoisMultiply(3, state[col+1]) ^ state[col+2] ^ state[col+3];
    result[col+1] = state[col] ^ galoisMultiply(2, state[col+1]) ^ galoisMultiply(3, state[col+2]) ^ state[col+3];
    result[col+2] = state[col] ^ state[col+1] ^ galoisMultiply(2, state[col+2]) ^ galoisMultiply(3, state[col+3]);
    result[col+3] = galoisMultiply(3, state[col]) ^ state[col+1] ^ state[col+2] ^ galoisMultiply(2, state[col+3]);
  }
  
  return result;
};

/**
 * Performs the inverse MixColumns operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @returns {Uint8Array} - The state after InvMixColumns
 */
const invMixColumns = (state) => {
  const result = new Uint8Array(16);
  
  for (let i = 0; i < 4; i++) {
    const col = i * 4;
    result[col] = galoisMultiply(0x0e, state[col]) ^ galoisMultiply(0x0b, state[col+1]) ^ 
                  galoisMultiply(0x0d, state[col+2]) ^ galoisMultiply(0x09, state[col+3]);
    result[col+1] = galoisMultiply(0x09, state[col]) ^ galoisMultiply(0x0e, state[col+1]) ^ 
                    galoisMultiply(0x0b, state[col+2]) ^ galoisMultiply(0x0d, state[col+3]);
    result[col+2] = galoisMultiply(0x0d, state[col]) ^ galoisMultiply(0x09, state[col+1]) ^ 
                    galoisMultiply(0x0e, state[col+2]) ^ galoisMultiply(0x0b, state[col+3]);
    result[col+3] = galoisMultiply(0x0b, state[col]) ^ galoisMultiply(0x0d, state[col+1]) ^ 
                    galoisMultiply(0x09, state[col+2]) ^ galoisMultiply(0x0e, state[col+3]);
  }
  
  return result;
};

/**
 * Performs the AddRoundKey operation on a state matrix
 * @param {Uint8Array} state - The state matrix
 * @param {Uint8Array} roundKey - The round key
 * @returns {Uint8Array} - The state after AddRoundKey
 */
const addRoundKey = (state, roundKey) => {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = state[i] ^ roundKey[i];
  }
  return result;
};

/**
 * Expands the cipher key into the round keys
 * @param {Uint8Array} key - The cipher key
 * @param {number} keySize - The key size in bits (128 or 256)
 * @returns {Uint8Array} - The expanded key
 */
const keyExpansion = (key, keySize) => {
  const Nk = keySize / 32; // Number of 32-bit words in the key
  const Nr = Nk + 6; // Number of rounds
  const Nb = 4; // Number of columns in state (fixed for AES)
  
  const w = new Uint32Array(Nb * (Nr + 1));
  const expandedKey = new Uint8Array(4 * Nb * (Nr + 1));
  
  // Copy the key into the first Nk words
  for (let i = 0; i < Nk; i++) {
    w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
  }
  
  // Generate the rest of the expanded key
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i-1];
    
    if (i % Nk === 0) {
      // RotWord: Rotate the word
      temp = ((temp << 8) | ((temp >> 24) & 0xff)) & 0xffffffff;
      
      // SubWord: Apply S-box to each byte
      const b0 = SBOX[(temp >> 24) & 0xff];
      const b1 = SBOX[(temp >> 16) & 0xff];
      const b2 = SBOX[(temp >> 8) & 0xff];
      const b3 = SBOX[temp & 0xff];
      
      temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
      
      // XOR with Rcon
      temp ^= (RCON[(i / Nk) - 1] << 24);
    } else if (Nk > 6 && i % Nk === 4) {
      // SubWord for AES-256
      const b0 = SBOX[(temp >> 24) & 0xff];
      const b1 = SBOX[(temp >> 16) & 0xff];
      const b2 = SBOX[(temp >> 8) & 0xff];
      const b3 = SBOX[temp & 0xff];
      
      temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }
    
    w[i] = w[i - Nk] ^ temp;
  }
  
  // Convert to byte array
  for (let i = 0; i < Nb * (Nr + 1); i++) {
    expandedKey[4*i] = (w[i] >> 24) & 0xff;
    expandedKey[4*i+1] = (w[i] >> 16) & 0xff;
    expandedKey[4*i+2] = (w[i] >> 8) & 0xff;
    expandedKey[4*i+3] = w[i] & 0xff;
  }
  
  return expandedKey;
};

/**
 * Encrypts a block of data using AES
 * @param {Uint8Array} block - The 16-byte block to encrypt
 * @param {Uint8Array} expandedKey - The expanded key
 * @param {number} keySize - The key size in bits (128 or 256)
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {Uint8Array} - The encrypted block
 */
const encryptBlock = (block, expandedKey, keySize, steps) => {
  const Nr = keySize / 32 + 6; // Number of rounds
  
  let state = new Uint8Array(block);
  
  // Record initial state
  steps.push({
    title: 'Initial State',
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The initial input block before any transformations.'
  });
  
  // Initial round key addition
  state = addRoundKey(state, expandedKey.slice(0, 16));
  
  steps.push({
    title: 'AddRoundKey (Initial)',
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'XOR the state with the first round key (derived from the cipher key).'
  });
  
  // Main rounds
  for (let round = 1; round < Nr; round++) {
    state = subBytes(state);
    steps.push({
      title: `Round ${round} - SubBytes`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Apply the S-box substitution to each byte of the state.'
    });
    
    state = shiftRows(state);
    steps.push({
      title: `Round ${round} - ShiftRows`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Cyclically shift the rows of the state.'
    });
    
    state = mixColumns(state);
    steps.push({
      title: `Round ${round} - MixColumns`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Mix the columns of the state using a linear transformation.'
    });
    
    state = addRoundKey(state, expandedKey.slice(16 * round, 16 * (round + 1)));
    steps.push({
      title: `Round ${round} - AddRoundKey`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `XOR the state with the round key for round ${round}.`
    });
  }
  
  // Final round (no MixColumns)
  state = subBytes(state);
  steps.push({
    title: `Round ${Nr} - SubBytes (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'Apply the S-box substitution to each byte of the state in the final round.'
  });
  
  state = shiftRows(state);
  steps.push({
    title: `Round ${Nr} - ShiftRows (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'Cyclically shift the rows of the state in the final round.'
  });
  
  state = addRoundKey(state, expandedKey.slice(16 * Nr, 16 * (Nr + 1)));
  steps.push({
    title: `Round ${Nr} - AddRoundKey (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'XOR the state with the final round key.'
  });
  
  return state;
};

/**
 * Decrypts a block of data using AES
 * @param {Uint8Array} block - The 16-byte block to decrypt
 * @param {Uint8Array} expandedKey - The expanded key
 * @param {number} keySize - The key size in bits (128 or 256)
 * @param {Array} steps - Array to store the steps of the decryption process
 * @returns {Uint8Array} - The decrypted block
 */
const decryptBlock = (block, expandedKey, keySize, steps) => {
  const Nr = keySize / 32 + 6; // Number of rounds
  
  let state = new Uint8Array(block);
  
  // Record initial state
  steps.push({
    title: 'Initial Ciphertext State',
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The initial ciphertext block before any transformations.'
  });
  
  // Initial round key addition (with the last round key)
  state = addRoundKey(state, expandedKey.slice(16 * Nr, 16 * (Nr + 1)));
  
  steps.push({
    title: 'AddRoundKey (Initial)',
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'XOR the state with the last round key.'
  });
  
  // Main rounds (in reverse)
  for (let round = Nr - 1; round > 0; round--) {
    state = invShiftRows(state);
    steps.push({
      title: `Round ${Nr - round} - InvShiftRows`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Inverse cyclically shift the rows of the state.'
    });
    
    state = invSubBytes(state);
    steps.push({
      title: `Round ${Nr - round} - InvSubBytes`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Apply the inverse S-box substitution to each byte of the state.'
    });
    
    state = addRoundKey(state, expandedKey.slice(16 * round, 16 * (round + 1)));
    steps.push({
      title: `Round ${Nr - round} - AddRoundKey`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `XOR the state with the round key for round ${round}.`
    });
    
    state = invMixColumns(state);
    steps.push({
      title: `Round ${Nr - round} - InvMixColumns`,
      hex: bytesToHex(state),
      binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: 'Apply inverse mix columns transformation.'
    });
  }
  
  // Final round (no InvMixColumns)
  state = invShiftRows(state);
  steps.push({
    title: `Round ${Nr} - InvShiftRows (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'Inverse cyclically shift the rows of the state in the final round.'
  });
  
  state = invSubBytes(state);
  steps.push({
    title: `Round ${Nr} - InvSubBytes (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'Apply the inverse S-box substitution to each byte of the state in the final round.'
  });
  
  state = addRoundKey(state, expandedKey.slice(0, 16));
  steps.push({
    title: `Round ${Nr} - AddRoundKey (Final)`,
    hex: bytesToHex(state),
    binary: Array.from(state).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'XOR the state with the first round key.'
  });
  
  return state;
};

/**
 * Performs AES encryption on the input text
 * @param {string} input - The plaintext to encrypt
 * @param {string} keyHex - The encryption key in hexadecimal
 * @param {number} keySize - The key size in bits (128 or 256)
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {string} - The encrypted ciphertext in hexadecimal
 */
export const encryptAES = (input, keyHex, keySize, steps) => {
  // Normalize and validate the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  const expectedKeyLength = keySize / 8 * 2; // Each byte is 2 hex chars
  
  if (keyHex.length !== expectedKeyLength) {
    throw new Error(`AES-${keySize} requires a ${keySize/8}-byte (${expectedKeyLength} hex characters) key`);
  }
  
  // Convert key from hex to bytes
  const key = hexToBytes(keyHex);
  
  steps.push({
    title: 'Key',
    hex: keyHex,
    binary: Array.from(key).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `The ${keySize}-bit encryption key.`
  });
  
  // Expand the key
  const expandedKey = keyExpansion(key, keySize);
  
  steps.push({
    title: 'Key Expansion',
    hex: bytesToHex(expandedKey),
    binary: Array.from(expandedKey).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `Expand the ${keySize}-bit cipher key into the round keys using the key schedule.`
  });
  
  // Convert input to bytes
  const encoder = new TextEncoder();
  const inputBytes = encoder.encode(input);
  
  steps.push({
    title: 'Input Text',
    hex: bytesToHex(inputBytes),
    binary: Array.from(inputBytes).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The plaintext converted to bytes.'
  });
  
  // Pad the input to a multiple of 16 bytes (PKCS#7 padding)
  const paddingLength = 16 - (inputBytes.length % 16);
  const paddedInput = new Uint8Array(inputBytes.length + paddingLength);
  paddedInput.set(inputBytes);
  
  // Add PKCS#7 padding
  for (let i = inputBytes.length; i < paddedInput.length; i++) {
    paddedInput[i] = paddingLength;
  }
  
  steps.push({
    title: 'PKCS#7 Padding',
    hex: bytesToHex(paddedInput),
    binary: Array.from(paddedInput).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `Pad the input to a multiple of 16 bytes using PKCS#7 padding (added ${paddingLength} bytes with value ${paddingLength}).`
  });
  
  // Encrypt each block
  const numBlocks = paddedInput.length / 16;
  const ciphertext = new Uint8Array(paddedInput.length);
  
  for (let i = 0; i < numBlocks; i++) {
    const block = paddedInput.slice(i * 16, (i + 1) * 16);
    
    steps.push({
      title: `Block ${i + 1}`,
      hex: bytesToHex(block),
      binary: Array.from(block).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `Plaintext block ${i + 1} to be encrypted.`
    });
    
    const encryptedBlock = encryptBlock(block, expandedKey, keySize, steps);
    ciphertext.set(encryptedBlock, i * 16);
    
    steps.push({
      title: `Block ${i + 1} - Encrypted`,
      hex: bytesToHex(encryptedBlock),
      binary: Array.from(encryptedBlock).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `Final encrypted block ${i + 1}.`
    });
  }
  
  // Convert the ciphertext to hexadecimal
  const ciphertextHex = bytesToHex(ciphertext);
  
  steps.push({
    title: 'Final Ciphertext',
    hex: ciphertextHex,
    binary: Array.from(ciphertext).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The complete encrypted ciphertext in hexadecimal format.'
  });
  
  return ciphertextHex;
};

/**
 * Performs AES decryption on the input ciphertext
 * @param {string} ciphertextHex - The ciphertext in hexadecimal
 * @param {string} keyHex - The decryption key in hexadecimal
 * @param {number} keySize - The key size in bits (128 or 256)
 * @param {Array} steps - Array to store the steps of the decryption process
 * @returns {string} - The decrypted plaintext
 */
export const decryptAES = (ciphertextHex, keyHex, keySize, steps) => {
  // Normalize and validate the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  const expectedKeyLength = keySize / 8 * 2; // Each byte is 2 hex chars
  
  if (keyHex.length !== expectedKeyLength) {
    throw new Error(`AES-${keySize} requires a ${keySize/8}-byte (${expectedKeyLength} hex characters) key`);
  }
  
  // Convert key from hex to bytes
  const key = hexToBytes(keyHex);
  
  steps.push({
    title: 'Key',
    hex: keyHex,
    binary: Array.from(key).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `The ${keySize}-bit decryption key.`
  });
  
  // Expand the key
  const expandedKey = keyExpansion(key, keySize);
  
  steps.push({
    title: 'Key Expansion',
    hex: bytesToHex(expandedKey),
    binary: Array.from(expandedKey).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `Expand the ${keySize}-bit cipher key into the round keys using the key schedule.`
  });
  
  // Normalize ciphertext
  ciphertextHex = ciphertextHex.replace(/[^0-9A-Fa-f]/g, '');
  
  // Validate ciphertext length
  if (ciphertextHex.length % 32 !== 0) { // 32 hex chars = 16 bytes
    throw new Error('Ciphertext length must be a multiple of 16 bytes (32 hex characters)');
  }
  
  // Convert ciphertext from hex to bytes
  const ciphertext = hexToBytes(ciphertextHex);
  
  steps.push({
    title: 'Ciphertext',
    hex: ciphertextHex,
    binary: Array.from(ciphertext).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The ciphertext to be decrypted.'
  });
  
  // Decrypt each block
  const numBlocks = ciphertext.length / 16;
  const decrypted = new Uint8Array(ciphertext.length);
  
  for (let i = 0; i < numBlocks; i++) {
    const block = ciphertext.slice(i * 16, (i + 1) * 16);
    
    steps.push({
      title: `Block ${i + 1}`,
      hex: bytesToHex(block),
      binary: Array.from(block).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `Ciphertext block ${i + 1} to be decrypted.`
    });
    
    const decryptedBlock = decryptBlock(block, expandedKey, keySize, steps);
    decrypted.set(decryptedBlock, i * 16);
    
    steps.push({
      title: `Block ${i + 1} - Decrypted`,
      hex: bytesToHex(decryptedBlock),
      binary: Array.from(decryptedBlock).map(b => b.toString(2).padStart(8, '0')).join(' '),
      description: `Decrypted block ${i + 1} (with padding).`
    });
  }
  
  // Remove PKCS#7 padding
  const paddingValue = decrypted[decrypted.length - 1];
  let paddingValid = true;
  
  // Validate padding
  if (paddingValue > 0 && paddingValue <= 16) {
    for (let i = decrypted.length - paddingValue; i < decrypted.length; i++) {
      if (decrypted[i] !== paddingValue) {
        paddingValid = false;
        break;
      }
    }
  } else {
    paddingValid = false;
  }
  
  if (!paddingValid) {
    throw new Error('Invalid padding in decrypted data');
  }
  
  // Remove padding
  const unpadded = decrypted.slice(0, decrypted.length - paddingValue);
  
  steps.push({
    title: 'Remove PKCS#7 Padding',
    hex: bytesToHex(unpadded),
    binary: Array.from(unpadded).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: `Removed ${paddingValue} bytes of padding.`
  });
  
  // Convert bytes to text
  const decoder = new TextDecoder();
  const plaintext = decoder.decode(unpadded);
  
  steps.push({
    title: 'Final Plaintext',
    hex: bytesToHex(unpadded),
    binary: Array.from(unpadded).map(b => b.toString(2).padStart(8, '0')).join(' '),
    description: 'The complete decrypted plaintext.'
  });
  
  return plaintext;
};
