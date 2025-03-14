/**
 * DES (Data Encryption Standard) implementation
 * 
 * This implementation follows the FIPS 46-3 specification
 * and includes comprehensive step-by-step visualization
 */

// Initial Permutation (IP) table
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
];

// Final Permutation (IP^-1) table
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25
];

// Expansion (E) table
const E = [
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1
];

// Permutation (P) table
const P = [
  16, 7, 20, 21, 29, 12, 28, 17,
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25
];

// Permuted Choice 1 (PC1) table
const PC1 = [
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4
];

// Permuted Choice 2 (PC2) table
const PC2 = [
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
];

// Left shifts for each round in key generation
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// S-Boxes (Substitution boxes)
const SBOXES = [
  // S1
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
  ],
  // S2
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
  ],
  // S3
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
  ],
  // S4
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
  ],
  // S5
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
  ],
  // S6
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
  ],
  // S7
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
  ],
  // S8
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
  ]
];

/**
 * Converts a hexadecimal string to a binary string
 * @param {string} hex - Hexadecimal string
 * @returns {string} - Binary string
 */
const hexToBin = (hex) => {
  hex = hex.replace(/[^0-9A-Fa-f]/g, '');
  let bin = '';
  for (let i = 0; i < hex.length; i++) {
    bin += parseInt(hex[i], 16).toString(2).padStart(4, '0');
  }
  return bin;
};

/**
 * Converts a binary string to a hexadecimal string
 * @param {string} bin - Binary string
 * @returns {string} - Hexadecimal string
 */
const binToHex = (bin) => {
  let hex = '';
  for (let i = 0; i < bin.length; i += 4) {
    hex += parseInt(bin.substr(i, 4), 2).toString(16);
  }
  return hex;
};

/**
 * Converts a string to a binary string
 * @param {string} str - String to convert
 * @returns {string} - Binary string
 */
const strToBin = (str) => {
  let bin = '';
  for (let i = 0; i < str.length; i++) {
    bin += str.charCodeAt(i).toString(2).padStart(8, '0');
  }
  return bin;
};

/**
 * Converts a binary string to a string
 * @param {string} bin - Binary string
 * @returns {string} - String
 */
const binToStr = (bin) => {
  let str = '';
  for (let i = 0; i < bin.length; i += 8) {
    str += String.fromCharCode(parseInt(bin.substr(i, 8), 2));
  }
  return str;
};

/**
 * Applies a permutation to a binary string using a table
 * @param {string} bin - Binary string
 * @param {Array} table - Permutation table
 * @returns {string} - Permuted binary string
 */
const permute = (bin, table) => {
  let result = '';
  for (let i = 0; i < table.length; i++) {
    result += bin.charAt(table[i] - 1);
  }
  return result;
};

/**
 * Performs a circular left shift on a binary string
 * @param {string} bin - Binary string
 * @param {number} shift - Number of positions to shift
 * @returns {string} - Shifted binary string
 */
const leftShift = (bin, shift) => {
  return bin.substring(shift) + bin.substring(0, shift);
};

/**
 * Generates 16 subkeys for DES encryption/decryption
 * @param {string} keyHex - Key in hexadecimal
 * @param {Array} steps - Array to store the steps of the key generation process
 * @returns {Array} - Array of 16 subkeys
 */
const generateSubkeys = (keyHex, steps) => {
  // Convert key from hex to binary
  let keyBin = hexToBin(keyHex);
  
  // Ensure the key is 64 bits
  keyBin = keyBin.padEnd(64, '0').substring(0, 64);
  
  steps.push({
    title: 'Original Key',
    hex: keyHex,
    binary: keyBin,
    description: 'The original 64-bit key in binary format.'
  });
  
  // Apply PC1 permutation to get 56-bit key
  const keyPC1 = permute(keyBin, PC1);
  
  steps.push({
    title: 'PC1 Permutation',
    hex: binToHex(keyPC1),
    binary: keyPC1,
    description: 'Apply Permuted Choice 1 (PC1) to reduce the key from 64 to 56 bits (removing parity bits).'
  });
  
  // Split into left and right halves (28 bits each)
  let C = keyPC1.substring(0, 28);
  let D = keyPC1.substring(28);
  
  steps.push({
    title: 'Split Key',
    hex: binToHex(C) + ' | ' + binToHex(D),
    binary: C + ' | ' + D,
    description: 'Split the 56-bit key into two 28-bit halves: C0 and D0.'
  });
  
  // Generate 16 subkeys
  const subkeys = [];
  
  for (let i = 0; i < 16; i++) {
    // Apply left shifts
    C = leftShift(C, SHIFTS[i]);
    D = leftShift(D, SHIFTS[i]);
    
    steps.push({
      title: `Round ${i + 1} Shifts`,
      hex: binToHex(C) + ' | ' + binToHex(D),
      binary: C + ' | ' + D,
      description: `Apply ${SHIFTS[i]} left shift(s) to both halves (C${i} and D${i}).`
    });
    
    // Combine and apply PC2 permutation
    const combined = C + D;
    const subkey = permute(combined, PC2);
    
    steps.push({
      title: `Subkey ${i + 1}`,
      hex: binToHex(subkey),
      binary: subkey,
      description: `Apply Permuted Choice 2 (PC2) to get the 48-bit subkey K${i + 1}.`
    });
    
    subkeys.push(subkey);
  }
  
  return subkeys;
};

/**
 * Expands a 32-bit block to 48 bits using the E table
 * @param {string} block - 32-bit block
 * @returns {string} - 48-bit expanded block
 */
const expand = (block) => {
  return permute(block, E);
};

/**
 * Applies the S-Box substitution to a 48-bit block
 * @param {string} block - 48-bit block
 * @returns {string} - 32-bit block after S-Box substitution
 */
const substitute = (block) => {
  let result = '';
  
  // Process 6 bits at a time
  for (let i = 0; i < 8; i++) {
    const chunk = block.substring(i * 6, (i + 1) * 6);
    
    // Calculate row and column indices
    const row = parseInt(chunk.charAt(0) + chunk.charAt(5), 2);
    const col = parseInt(chunk.substring(1, 5), 2);
    
    // Lookup value in S-Box
    const value = SBOXES[i][row][col];
    
    // Convert to 4-bit binary
    result += value.toString(2).padStart(4, '0');
  }
  
  return result;
};

/**
 * Performs the DES Feistel function on a 32-bit half with a 48-bit subkey
 * @param {string} half - 32-bit half
 * @param {string} subkey - 48-bit subkey
 * @param {Array} steps - Array to store the steps of the function
 * @param {number} round - Current round number
 * @returns {string} - 32-bit result
 */
const feistel = (half, subkey, steps, round) => {
  // Expand 32-bit half to 48 bits
  const expanded = expand(half);
  
  steps.push({
    title: `Round ${round} - Expansion`,
    hex: binToHex(expanded),
    binary: expanded,
    description: 'Expand the 32-bit right half to 48 bits using the E-table.'
  });
  
  // XOR with subkey
  let xored = '';
  for (let i = 0; i < 48; i++) {
    xored += (expanded.charAt(i) === subkey.charAt(i)) ? '0' : '1';
  }
  
  steps.push({
    title: `Round ${round} - Key Mixing`,
    hex: binToHex(xored),
    binary: xored,
    description: 'XOR the expanded block with the subkey.'
  });
  
  // Apply S-Box substitution
  const substituted = substitute(xored);
  
  steps.push({
    title: `Round ${round} - S-Box Substitution`,
    hex: binToHex(substituted),
    binary: substituted,
    description: 'Apply the S-Box substitution to get a 32-bit result.'
  });
  
  // Apply P permutation
  const permuted = permute(substituted, P);
  
  steps.push({
    title: `Round ${round} - P Permutation`,
    hex: binToHex(permuted),
    binary: permuted,
    description: 'Apply the P permutation for the final result of the Feistel function.'
  });
  
  return permuted;
};

/**
 * Encrypts a 64-bit block using DES
 * @param {string} blockBin - 64-bit block in binary
 * @param {Array} subkeys - Array of 16 subkeys
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {string} - Encrypted 64-bit block in binary
 */
const encryptBlock = (blockBin, subkeys, steps) => {
  // Initial permutation
  const ip = permute(blockBin, IP);
  
  steps.push({
    title: 'Initial Permutation',
    hex: binToHex(ip),
    binary: ip,
    description: 'Apply the Initial Permutation (IP) to the input block.'
  });
  
  // Split into left and right halves
  let L = ip.substring(0, 32);
  let R = ip.substring(32);
  
  steps.push({
    title: 'Split Block',
    hex: binToHex(L) + ' | ' + binToHex(R),
    binary: L + ' | ' + R,
    description: 'Split the 64-bit block into two 32-bit halves: L0 and R0.'
  });
  
  // 16 rounds of encryption
  for (let i = 0; i < 16; i++) {
    // Store the original right half
    const R_prev = R;
    
    // Calculate new right half
    R = L;
    
    // Calculate new left half
    const feistelResult = feistel(R_prev, subkeys[i], steps, i + 1);
    
    // XOR with previous left half
    L = '';
    for (let j = 0; j < 32; j++) {
      L += (R_prev.charAt(j) === feistelResult.charAt(j)) ? '0' : '1';
    }
    
    steps.push({
      title: `Round ${i + 1} - Result`,
      hex: binToHex(L) + ' | ' + binToHex(R),
      binary: L + ' | ' + R,
      description: `New values after round ${i + 1}: L${i + 1} = R${i}, R${i + 1} = L${i} XOR F(R${i}, K${i + 1}).`
    });
  }
  
  // Final block is RL (reversed) due to the Feistel structure
  const combined = R + L;
  
  steps.push({
    title: 'Swap Halves',
    hex: binToHex(combined),
    binary: combined,
    description: 'Swap the left and right halves after the 16 rounds.'
  });
  
  // Final permutation
  const encrypted = permute(combined, FP);
  
  steps.push({
    title: 'Final Permutation',
    hex: binToHex(encrypted),
    binary: encrypted,
    description: 'Apply the Final Permutation (FP) to get the ciphertext block.'
  });
  
  return encrypted;
};

/**
 * Decrypts a 64-bit block using DES
 * @param {string} blockBin - 64-bit block in binary
 * @param {Array} subkeys - Array of 16 subkeys
 * @param {Array} steps - Array to store the steps of the decryption process
 * @returns {string} - Decrypted 64-bit block in binary
 */
const decryptBlock = (blockBin, subkeys, steps) => {
  // For decryption, use the subkeys in reverse order
  const reversedSubkeys = [...subkeys].reverse();
  
  // Use the same algorithm as encryption with reversed subkeys
  return encryptBlock(blockBin, reversedSubkeys, steps);
};

/**
 * Performs DES encryption on the input text
 * @param {string} input - The plaintext to encrypt
 * @param {string} keyHex - The encryption key in hexadecimal
 * @param {Array} steps - Array to store the steps of the encryption process
 * @returns {string} - The encrypted ciphertext in hexadecimal
 */
export const encryptDES = (input, keyHex, steps) => {
  // Normalize the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  
  // Ensure the key is 64 bits (8 bytes = 16 hex characters)
  if (keyHex.length > 16) {
    keyHex = keyHex.substring(0, 16);
  } else if (keyHex.length < 16) {
    keyHex = keyHex.padEnd(16, '0');
  }
  
  steps.push({
    title: 'Normalized Key',
    hex: keyHex,
    binary: hexToBin(keyHex),
    description: 'The 64-bit encryption key in hexadecimal format.'
  });
  
  // Generate subkeys
  const subkeys = generateSubkeys(keyHex, steps);
  
  // Convert the input to binary
  let inputBin = '';
  if (/^[0-9A-Fa-f]+$/.test(input)) {
    // Input is already in hex format
    inputBin = hexToBin(input);
  } else {
    // Input is text
    inputBin = strToBin(input);
  }
  
  steps.push({
    title: 'Input Text (Binary)',
    hex: binToHex(inputBin),
    binary: inputBin,
    description: 'The plaintext converted to binary format.'
  });
  
  // Pad the input to a multiple of 64 bits (8 bytes)
  const paddingLength = 64 - (inputBin.length % 64);
  const paddedInput = inputBin + '0'.repeat(paddingLength);
  
  steps.push({
    title: 'Padded Input',
    hex: binToHex(paddedInput),
    binary: paddedInput,
    description: `Padded the input to a multiple of 64 bits by adding ${paddingLength} bits.`
  });
  
  // Process each 64-bit block
  let cipherBin = '';
  for (let i = 0; i < paddedInput.length; i += 64) {
    const block = paddedInput.substring(i, i + 64);
    
    steps.push({
      title: `Block ${i/64 + 1}`,
      hex: binToHex(block),
      binary: block,
      description: `Processing 64-bit block ${i/64 + 1}.`
    });
    
    const encryptedBlock = encryptBlock(block, subkeys, steps);
    cipherBin += encryptedBlock;
    
    steps.push({
      title: `Block ${i/64 + 1} - Encrypted`,
      hex: binToHex(encryptedBlock),
      binary: encryptedBlock,
      description: `Encrypted 64-bit block ${i/64 + 1}.`
    });
  }
  
  // Convert the result to hexadecimal
  const cipherHex = binToHex(cipherBin);
  
  steps.push({
    title: 'Final Ciphertext',
    hex: cipherHex,
    binary: cipherBin,
    description: 'The complete encrypted ciphertext in hexadecimal format.'
  });
  
  return cipherHex;
};

/**
 * Performs DES decryption on the input ciphertext
 * @param {string} ciphertextHex - The ciphertext in hexadecimal
 * @param {string} keyHex - The decryption key in hexadecimal
 * @param {Array} steps - Array to store the steps of the decryption process
 * @returns {string} - The decrypted plaintext
 */
export const decryptDES = (ciphertextHex, keyHex, steps) => {
  // Normalize the key
  keyHex = keyHex.replace(/[^0-9A-Fa-f]/g, '');
  
  // Ensure the key is 64 bits (8 bytes = 16 hex characters)
  if (keyHex.length > 16) {
    keyHex = keyHex.substring(0, 16);
  } else if (keyHex.length < 16) {
    keyHex = keyHex.padEnd(16, '0');
  }
  
  steps.push({
    title: 'Normalized Key',
    hex: keyHex,
    binary: hexToBin(keyHex),
    description: 'The 64-bit decryption key in hexadecimal format.'
  });
  
  // Generate subkeys
  const subkeys = generateSubkeys(keyHex, steps);
  
  // Normalize the ciphertext
  ciphertextHex = ciphertextHex.replace(/[^0-9A-Fa-f]/g, '');
  
  steps.push({
    title: 'Ciphertext',
    hex: ciphertextHex,
    binary: hexToBin(ciphertextHex),
    description: 'The ciphertext in hexadecimal format.'
  });
  
  // Convert the ciphertext to binary
  const cipherBin = hexToBin(ciphertextHex);
  
  // Ensure the ciphertext length is a multiple of 64 bits
  if (cipherBin.length % 64 !== 0) {
    throw new Error('Invalid ciphertext length. Must be a multiple of 64 bits.');
  }
  
  // Process each 64-bit block
  let plainBin = '';
  for (let i = 0; i < cipherBin.length; i += 64) {
    const block = cipherBin.substring(i, i + 64);
    
    steps.push({
      title: `Block ${i/64 + 1}`,
      hex: binToHex(block),
      binary: block,
      description: `Processing 64-bit ciphertext block ${i/64 + 1}.`
    });
    
    const decryptedBlock = decryptBlock(block, subkeys, steps);
    plainBin += decryptedBlock;
    
    steps.push({
      title: `Block ${i/64 + 1} - Decrypted`,
      hex: binToHex(decryptedBlock),
      binary: decryptedBlock,
      description: `Decrypted 64-bit block ${i/64 + 1}.`
    });
  }
  
  // Remove padding (assuming zero-padding)
  let unpadded = plainBin;
  while (unpadded.length > 0 && unpadded.charAt(unpadded.length - 1) === '0') {
    unpadded = unpadded.substring(0, unpadded.length - 1);
  }
  
  // Make sure length is a multiple of 8 (for char conversion)
  if (unpadded.length % 8 !== 0) {
    unpadded = unpadded.substring(0, unpadded.length - (unpadded.length % 8));
  }
  
  steps.push({
    title: 'Unpadded Binary',
    hex: binToHex(unpadded),
    binary: unpadded,
    description: 'The decrypted binary data with padding removed.'
  });
  
  // Try to convert to text (if it was originally text)
  try {
    const plaintext = binToStr(unpadded);
    
    // Check if the result is printable ASCII
    const isPrintableAscii = plaintext.split('').every(char => {
      const code = char.charCodeAt(0);
      return code >= 32 && code < 127;
    });
    
    if (isPrintableAscii) {
      steps.push({
        title: 'Final Plaintext',
        hex: binToHex(unpadded),
        binary: unpadded,
        description: 'The decrypted text in ASCII format.'
      });
      
      return plaintext;
    }
  } catch (error) {
    // Not valid UTF-8, return hex instead
  }
  
  // Return as hex if not valid text
  const plainHex = binToHex(unpadded);
  
  steps.push({
    title: 'Final Plaintext (Hex)',
    hex: plainHex,
    binary: unpadded,
    description: 'The decrypted data in hexadecimal format (not convertible to text).'
  });
  
  return plainHex;
};
