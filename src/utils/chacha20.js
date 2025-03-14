/**
 * ChaCha20 stream cipher implementation
 * 
 * This implementation follows RFC 8439
 * and includes comprehensive step-by-step visualization
 */

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
 * Converts a 32-bit unsigned integer to a binary string
 * @param {number} num - 32-bit unsigned integer
 * @returns {string} - Binary string representation
 */
const uint32ToBinaryString = (num) => {
  return (num >>> 0).toString(2).padStart(32, '0');
};

/**
 * Converts a Uint8Array to a binary string
 * @param {Uint8Array} bytes - Byte array
 * @returns {string} - Binary string representation
 */
const bytesToBinaryString = (bytes) => {
  return Array.from(bytes)
    .map(byte => byte.toString(2).padStart(8, '0'))
    .join(' ');
};

/**
 * Rotates a 32-bit unsigned integer left by the specified number of bits
 * @param {number} value - The value to rotate
 * @param {number} shift - The number of bits to rotate by
 * @returns {number} - The rotated value
 */
const rotl32 = (value, shift) => {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
};

/**
 * Performs a quarter round operation on four 32-bit integers
 * @param {Array} state - The ChaCha20 state array
 * @param {number} a - Index of the first integer
 * @param {number} b - Index of the second integer
 * @param {number} c - Index of the third integer
 * @param {number} d - Index of the fourth integer
 * @param {Array} steps - Array to store the steps of the operation
 * @param {number} round - Current round number
 * @param {number} quarterRound - Current quarter round number
 */
const quarterRound = (state, a, b, c, d, steps, round, quarterRound) => {
  const stateBefore = [...state];
  
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 16);
  
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 12);
  
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 8);
  
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 7);
  
  steps.push({
    title: `Round ${round} - Quarter Round ${quarterRound}`,
    hex: `a: ${state[a].toString(16).padStart(8, '0')}, b: ${state[b].toString(16).padStart(8, '0')}, c: ${state[c].toString(16).padStart(8, '0')}, d: ${state[d].toString(16).padStart(8, '0')}`,
    binary: `a: ${uint32ToBinaryString(state[a])}\nb: ${uint32ToBinaryString(state[b])}\nc: ${uint32ToBinaryString(state[c])}\nd: ${uint32ToBinaryString(state[d])}`,
    description: `Quarter round operation on indices ${a}, ${b}, ${c}, ${d}. Before: [${stateBefore[a]}, ${stateBefore[b]}, ${stateBefore[c]}, ${stateBefore[d]}]. After: [${state[a]}, ${state[b]}, ${state[c]}, ${state[d]}].`
  });
};

/**
 * Initializes the ChaCha20 state with key, nonce, and counter
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce - 12-byte nonce
 * @param {number} counter - 32-bit counter
 * @returns {Array} - 16 32-bit integers representing the ChaCha20 state
 */
const chacha20Init = (key, nonce, counter) => {
  // ChaCha20 constants (in hex: "expand 32-byte k")
  const state = [
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
    0, 0, 0, 0, 0, 0, 0, 0, // Key (8 words)
    0, // Counter
    0, 0, 0 // Nonce (3 words)
  ];
  
  // Add key (32 bytes = 8 words)
  for (let i = 0; i < 8; i++) {
    state[4 + i] = (key[i * 4] |
                   (key[i * 4 + 1] << 8) |
                   (key[i * 4 + 2] << 16) |
                   (key[i * 4 + 3] << 24)) >>> 0;
  }
  
  // Add counter
  state[12] = counter >>> 0;
  
  // Add nonce (12 bytes = 3 words)
  for (let i = 0; i < 3; i++) {
    state[13 + i] = (nonce[i * 4] |
                    (nonce[i * 4 + 1] << 8) |
                    (nonce[i * 4 + 2] << 16) |
                    (nonce[i * 4 + 3] << 24)) >>> 0;
  }
  
  return state;
};

/**
 * Generates a ChaCha20 keystream block
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce - 12-byte nonce
 * @param {number} counter - 32-bit counter
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {Uint8Array} - 64-byte keystream block
 */
const chacha20Block = (key, nonce, counter, steps) => {
  // Initialize state
  const state = chacha20Init(key, nonce, counter);
  
  steps.push({
    title: 'Initial State',
    hex: state.map(word => word.toString(16).padStart(8, '0')).join(' '),
    binary: state.map(word => uint32ToBinaryString(word)).join('\n'),
    description: 'The initial ChaCha20 state with constants, key, counter, and nonce.'
  });
  
  // Create a working copy of the state
  const workingState = [...state];
  
  // Apply 20 rounds (10 iterations of 8 quarter rounds each)
  for (let i = 0; i < 10; i++) {
    // Column round
    quarterRound(workingState, 0, 4, 8, 12, steps, i + 1, 1);
    quarterRound(workingState, 1, 5, 9, 13, steps, i + 1, 2);
    quarterRound(workingState, 2, 6, 10, 14, steps, i + 1, 3);
    quarterRound(workingState, 3, 7, 11, 15, steps, i + 1, 4);
    
    // Diagonal round
    quarterRound(workingState, 0, 5, 10, 15, steps, i + 1, 5);
    quarterRound(workingState, 1, 6, 11, 12, steps, i + 1, 6);
    quarterRound(workingState, 2, 7, 8, 13, steps, i + 1, 7);
    quarterRound(workingState, 3, 4, 9, 14, steps, i + 1, 8);
  }
  
  // Add the original state to the final state
  for (let i = 0; i < 16; i++) {
    workingState[i] = (workingState[i] + state[i]) >>> 0;
  }
  
  steps.push({
    title: 'Final State (after 20 rounds)',
    hex: workingState.map(word => word.toString(16).padStart(8, '0')).join(' '),
    binary: workingState.map(word => uint32ToBinaryString(word)).join('\n'),
    description: 'The final ChaCha20 state after applying 20 rounds of quarter round operations and adding the initial state.'
  });
  
  // Serialize the state to bytes
  const output = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const word = workingState[i];
    output[i * 4] = word & 0xff;
    output[i * 4 + 1] = (word >>> 8) & 0xff;
    output[i * 4 + 2] = (word >>> 16) & 0xff;
    output[i * 4 + 3] = (word >>> 24) & 0xff;
  }
  
  steps.push({
    title: 'Keystream Block',
    hex: bytesToHex(output),
    binary: bytesToBinaryString(output),
    description: 'The 64-byte keystream block generated from the final state.'
  });
  
  return output;
};

/**
 * XORs a keystream with input data
 * @param {Uint8Array} keystream - Keystream bytes
 * @param {Uint8Array} input - Input bytes
 * @returns {Uint8Array} - XORed output
 */
const xorKeystream = (keystream, input) => {
  const output = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    output[i] = keystream[i] ^ input[i];
  }
  return output;
};

/**
 * Encrypts data using the ChaCha20 stream cipher
 * @param {string} input - The plaintext to encrypt
 * @param {string} keyHex - The 32-byte encryption key in hexadecimal
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {string} - The encrypted ciphertext in hexadecimal
 */
export const encryptChaCha20 = (input, keyHex, steps) => {
  // Normalize and validate the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  if (keyHex.length !== 64) { // 32 bytes = 64 hex characters
    throw new Error('ChaCha20 requires a 32-byte (64 hex characters) key');
  }
  
  // Convert key from hex to bytes
  const key = hexToBytes(keyHex);
  
  steps.push({
    title: 'Key',
    hex: keyHex,
    binary: bytesToBinaryString(key),
    description: 'The 32-byte (256-bit) encryption key.'
  });
  
  // Generate a random 12-byte nonce
  const nonce = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    nonce[i] = Math.floor(Math.random() * 256);
  }
  
  steps.push({
    title: 'Nonce',
    hex: bytesToHex(nonce),
    binary: bytesToBinaryString(nonce),
    description: 'The randomly generated 12-byte nonce.'
  });
  
  // Convert input to bytes
  const encoder = new TextEncoder();
  const inputBytes = encoder.encode(input);
  
  steps.push({
    title: 'Input Text',
    hex: bytesToHex(inputBytes),
    binary: bytesToBinaryString(inputBytes),
    description: 'The plaintext converted to bytes.'
  });
  
  // Encrypt the input
  const encrypted = new Uint8Array(inputBytes.length + 12); // Add space for nonce
  
  // Copy the nonce to the beginning of the output
  encrypted.set(nonce, 0);
  
  // Process the input in 64-byte blocks
  let counter = 1; // Start counter at 1
  
  for (let i = 0; i < inputBytes.length; i += 64) {
    // Generate keystream block
    const keystream = chacha20Block(key, nonce, counter, steps);
    
    // Calculate how many bytes to process in this block
    const blockSize = Math.min(64, inputBytes.length - i);
    
    // Extract the current block of input
    const inputBlock = inputBytes.slice(i, i + blockSize);
    
    steps.push({
      title: `Block ${counter} - Input`,
      hex: bytesToHex(inputBlock),
      binary: bytesToBinaryString(inputBlock),
      description: `Input block ${counter} (${blockSize} bytes).`
    });
    
    // XOR with keystream
    const encryptedBlock = xorKeystream(keystream.slice(0, blockSize), inputBlock);
    
    steps.push({
      title: `Block ${counter} - XOR with Keystream`,
      hex: bytesToHex(encryptedBlock),
      binary: bytesToBinaryString(encryptedBlock),
      description: `Input block ${counter} XORed with keystream.`
    });
    
    // Copy encrypted block to output
    encrypted.set(encryptedBlock, i + 12); // +12 to account for nonce
    
    // Increment counter
    counter++;
  }
  
  // Convert the result to hexadecimal
  const encryptedHex = bytesToHex(encrypted);
  
  steps.push({
    title: 'Final Ciphertext',
    hex: encryptedHex,
    binary: bytesToBinaryString(encrypted),
    description: 'The complete encrypted ciphertext in hexadecimal format. The first 12 bytes are the nonce.'
  });
  
  return encryptedHex;
};

/**
 * Decrypts data using the ChaCha20 stream cipher
 * @param {string} ciphertextHex - The ciphertext in hexadecimal
 * @param {string} keyHex - The 32-byte decryption key in hexadecimal
 * @param {Array} steps - Array to store the steps of the decryption process
 * @returns {string} - The decrypted plaintext
 */
export const decryptChaCha20 = (ciphertextHex, keyHex, steps) => {
  // Normalize and validate the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  if (keyHex.length !== 64) { // 32 bytes = 64 hex characters
    throw new Error('ChaCha20 requires a 32-byte (64 hex characters) key');
  }
  
  // Convert key from hex to bytes
  const key = hexToBytes(keyHex);
  
  steps.push({
    title: 'Key',
    hex: keyHex,
    binary: bytesToBinaryString(key),
    description: 'The 32-byte (256-bit) decryption key.'
  });
  
  // Convert ciphertext from hex to bytes
  const ciphertext = hexToBytes(ciphertextHex);
  
  if (ciphertext.length < 12) {
    throw new Error('Invalid ciphertext: too short');
  }
  
  // Extract nonce (first 12 bytes)
  const nonce = ciphertext.slice(0, 12);
  
  steps.push({
    title: 'Nonce',
    hex: bytesToHex(nonce),
    binary: bytesToBinaryString(nonce),
    description: 'The 12-byte nonce extracted from the ciphertext.'
  });
  
  // Extract encrypted data (remaining bytes)
  const encryptedData = ciphertext.slice(12);
  
  steps.push({
    title: 'Encrypted Data',
    hex: bytesToHex(encryptedData),
    binary: bytesToBinaryString(encryptedData),
    description: 'The encrypted data without the nonce.'
  });
  
  // Decrypt the data
  const decrypted = new Uint8Array(encryptedData.length);
  
  // Process the data in 64-byte blocks
  let counter = 1; // Start counter at 1
  
  for (let i = 0; i < encryptedData.length; i += 64) {
    // Generate keystream block
    const keystream = chacha20Block(key, nonce, counter, steps);
    
    // Calculate how many bytes to process in this block
    const blockSize = Math.min(64, encryptedData.length - i);
    
    // Extract the current block of encrypted data
    const encryptedBlock = encryptedData.slice(i, i + blockSize);
    
    steps.push({
      title: `Block ${counter} - Encrypted`,
      hex: bytesToHex(encryptedBlock),
      binary: bytesToBinaryString(encryptedBlock),
      description: `Encrypted block ${counter} (${blockSize} bytes).`
    });
    
    // XOR with keystream
    const decryptedBlock = xorKeystream(keystream.slice(0, blockSize), encryptedBlock);
    
    steps.push({
      title: `Block ${counter} - XOR with Keystream`,
      hex: bytesToHex(decryptedBlock),
      binary: bytesToBinaryString(decryptedBlock),
      description: `Encrypted block ${counter} XORed with keystream.`
    });
    
    // Copy decrypted block to output
    decrypted.set(decryptedBlock, i);
    
    // Increment counter
    counter++;
  }
  
  // Convert bytes to text
  const decoder = new TextDecoder();
  const plaintext = decoder.decode(decrypted);
  
  steps.push({
    title: 'Final Plaintext',
    hex: bytesToHex(decrypted),
    binary: bytesToBinaryString(decrypted),
    description: 'The complete decrypted plaintext.'
  });
  
  return plaintext;
};
