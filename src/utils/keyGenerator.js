/**
 * Secure key generation module for cryptographic operations
 * 
 * This module implements strong entropy collection and key derivation
 * following NIST recommendations and modern cryptographic standards.
 */

/**
 * Generates a cryptographically secure random number
 * @returns {number} - A random number between 0 and 1
 */
const secureRandom = () => {
  // Use the Web Crypto API for cryptographically secure random numbers
  const array = new Uint32Array(1);
  window.crypto.getRandomValues(array);
  return array[0] / 4294967295; // Normalize to [0, 1]
};

/**
 * Generates a cryptographically secure random byte array
 * @param {number} length - The number of bytes to generate
 * @returns {Uint8Array} - Array of random bytes
 */
const getRandomBytes = (length) => {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return bytes;
};

/**
 * Generates a cryptographically secure random hexadecimal string
 * @param {number} length - The number of bytes (half the hex length)
 * @returns {string} - Hexadecimal string
 */
const getRandomHex = (length) => {
  const bytes = getRandomBytes(length);
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Mixes additional entropy sources with the Web Crypto API
 * This is used to strengthen the randomness even further
 * @param {number} bytes - Number of bytes of entropy to generate
 * @returns {Uint8Array} - Entropy bytes with multiple sources mixed in
 */
const collectEntropyPool = async (bytes) => {
  // Start with cryptographically secure random bytes
  const primary = getRandomBytes(bytes);
  
  // Secondary entropy sources
  const entropy = {
    // High-resolution timing information (sub-millisecond)
    timing: performance.now(),
    
    // Date and timezone information
    date: new Date().getTime(),
    timezone: new Date().getTimezoneOffset(),
    
    // Screen and window information (if available)
    screenWidth: window.screen ? window.screen.width : 0,
    screenHeight: window.screen ? window.screen.height : 0,
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    
    // Device pixel ratio
    pixelRatio: window.devicePixelRatio || 1,
    
    // Navigator information
    platform: navigator.platform,
    userAgent: navigator.userAgent,
    
    // Memory information (if available)
    memory: performance.memory ? performance.memory.totalJSHeapSize : 0,
    
    // Random mouse entropy
    mouseEntropy: Array.from({ length: 10 }, () => Math.random()),
  };
  
  // Convert entropy object to a string and then to bytes
  const entropyStr = JSON.stringify(entropy);
  const encoder = new TextEncoder();
  const entropyBytes = encoder.encode(entropyStr);
  
  // Use SubtleCrypto to hash the entropy
  const entropyHash = await window.crypto.subtle.digest('SHA-256', entropyBytes);
  const secondaryEntropy = new Uint8Array(entropyHash);
  
  // Mix the primary and secondary entropy sources
  const result = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    result[i] = primary[i] ^ secondaryEntropy[i % secondaryEntropy.length];
  }
  
  return result;
};

/**
 * Derives a cryptographic key from a password using PBKDF2
 * @param {string} password - The password to derive the key from
 * @param {string} algorithm - The algorithm to generate the key for
 * @returns {Promise<string>} - The derived key in hexadecimal format
 */
export const deriveKeyFromPassword = async (password, algorithm) => {
  // Convert password to bytes
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);
  
  // Generate a salt
  const salt = getRandomBytes(16);
  
  // Determine key size based on algorithm
  let keyLength;
  if (algorithm === 'aes-128') {
    keyLength = 16; // 128 bits = 16 bytes
  } else if (algorithm === 'aes-256') {
    keyLength = 32; // 256 bits = 32 bytes
  } else if (algorithm === 'des') {
    keyLength = 8;  // 64 bits = 8 bytes
  } else if (algorithm === 'chacha20') {
    keyLength = 32; // 256 bits = 32 bytes
  } else {
    throw new Error('Unsupported algorithm');
  }
  
  // Import the password as a key
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  // Derive the key using PBKDF2
  const params = {
    name: 'PBKDF2',
    salt: salt,
    iterations: 100000, // High iteration count for security
    hash: 'SHA-256'
  };
  
  const derivedBits = await window.crypto.subtle.deriveBits(
    params,
    baseKey,
    keyLength * 8
  );
  
  // Convert to hex
  const derivedBytes = new Uint8Array(derivedBits);
  return Array.from(derivedBytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Generates a secure random key for the specified algorithm
 * @param {string} algorithm - The algorithm to generate the key for
 * @returns {string} - The generated key in hexadecimal format
 */
export const generateSecureKey = async (algorithm) => {
  // Determine key size based on algorithm
  let keyLength;
  if (algorithm === 'aes-128') {
    keyLength = 16; // 128 bits = 16 bytes
  } else if (algorithm === 'aes-256') {
    keyLength = 32; // 256 bits = 32 bytes
  } else if (algorithm === 'des') {
    keyLength = 8;  // 64 bits = 8 bytes
  } else if (algorithm === 'chacha20') {
    keyLength = 32; // 256 bits = 32 bytes
  } else {
    throw new Error('Unsupported algorithm');
  }
  
  // Collect entropy from multiple sources
  const entropyPool = await collectEntropyPool(keyLength * 2); // Extra entropy
  
  // Use the Web Crypto API to generate a key with this entropy
  const extractedEntropy = entropyPool.slice(0, keyLength);
  
  // Mix in with pure random values
  const cryptoRandom = getRandomBytes(keyLength);
  
  // Combine the entropy sources
  const combined = new Uint8Array(keyLength);
  for (let i = 0; i < keyLength; i++) {
    combined[i] = extractedEntropy[i] ^ cryptoRandom[i];
  }
  
  // Convert to hex
  return Array.from(combined)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Tests the randomness quality of the entropy generation
 * @param {number} samples - Number of samples to generate
 * @param {number} byteLength - Length of each sample in bytes
 * @returns {Object} - Test results
 */
export const testEntropyQuality = async (samples = 1000, byteLength = 32) => {
  const results = {
    byteCounts: Array(256).fill(0),
    bitCounts: Array(2).fill(0),
    samples: []
  };
  
  const totalBytes = samples * byteLength;
  
  for (let i = 0; i < samples; i++) {
    const entropy = await collectEntropyPool(byteLength);
    results.samples.push(Array.from(entropy));
    
    // Count byte and bit frequencies
    for (let j = 0; j < byteLength; j++) {
      const byte = entropy[j];
      results.byteCounts[byte]++;
      
      // Count individual bits
      for (let bit = 0; bit < 8; bit++) {
        const bitValue = (byte >> bit) & 1;
        results.bitCounts[bitValue]++;
      }
    }
  }
  
  // Calculate statistics
  const expectedByteFreq = totalBytes / 256;
  const byteChiSquared = results.byteCounts.reduce((sum, count) => {
    const diff = count - expectedByteFreq;
    return sum + (diff * diff) / expectedByteFreq;
  }, 0);
  
  const expectedBitFreq = totalBytes * 8 / 2;
  const bitChiSquared = results.bitCounts.reduce((sum, count) => {
    const diff = count - expectedBitFreq;
    return sum + (diff * diff) / expectedBitFreq;
  }, 0);
  
  return {
    totalSamples: samples,
    totalBytes: totalBytes,
    totalBits: totalBytes * 8,
    byteDistribution: {
      counts: results.byteCounts,
      expected: expectedByteFreq,
      chiSquared: byteChiSquared,
      // For 255 degrees of freedom, critical value at 0.05 is 293.25
      isRandom: byteChiSquared < 293.25
    },
    bitDistribution: {
      counts: results.bitCounts,
      expected: expectedBitFreq,
      chiSquared: bitChiSquared,
      // For 1 degree of freedom, critical value at 0.05 is 3.84
      isRandom: bitChiSquared < 3.84
    }
  };
};
