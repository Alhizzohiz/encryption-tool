import React, { useState, useEffect } from 'react';
import { encryptAES, decryptAES } from '../utils/aes';
import { encryptDES, decryptDES } from '../utils/des';
import { encryptChaCha20, decryptChaCha20 } from '../utils/chacha20';
import { generateSecureKey, deriveKeyFromPassword } from '../utils/keyGenerator';
import { saveToFile, loadFromFile } from '../utils/fileHandler';
import './EncryptionForm.css';

/**
 * The main form component for the encryption application
 * Handles all user interactions and displays the encryption/decryption process
 */
const EncryptionForm = () => {
  // State for form inputs and results
  const [mode, setMode] = useState('encrypt');
  const [algorithm, setAlgorithm] = useState('aes-128');
  const [inputType, setInputType] = useState('text');
  const [input, setInput] = useState('');
  const [key, setKey] = useState('');
  const [result, setResult] = useState('');
  const [steps, setSteps] = useState([]);
  const [loading, setLoading] = useState(false);
  
  
  /**
   * Generates a secure random key for the selected algorithm on press and change
   */
  const handleGenerateKey = async () => {
    setLoading(true);
    try {
      const newKey = await generateSecureKey(algorithm);
      setKey(newKey);
    } catch (error) {
      console.error('Error generating key:', error);
      alert(`Failed to generate key: ${error.message}`);
    }
    setLoading(false);
  };
  
  useEffect(() => {
  handleGenerateKey();
	}, [algorithm, handleGenerateKey]); 
  
  /**
   * Derives a key from a password for the selected algorithm
   */
  const handleDeriveKey = async () => {
    if (inputType === 'password' && input) {
      setLoading(true);
      try {
        const derivedKey = await deriveKeyFromPassword(input, algorithm);
        setKey(derivedKey);
      } catch (error) {
        console.error('Error deriving key:', error);
        alert(`Failed to derive key: ${error.message}`);
      }
      setLoading(false);
    }
  };
  
  /**
   * Handles encryption or decryption based on the current mode
   */
  const handleProcess = async () => {
    if (!input || !key) {
      alert('Please provide both input and key');
      return;
    }
    
    setLoading(true);
    setSteps([]);
    
    let processingSteps = [];
    let processedData = '';
    
    try {
      if (mode === 'encrypt') {
        // Encryption based on selected algorithm
        switch (algorithm) {
          case 'aes-128':
            processedData = await encryptAES(input, key, 128, processingSteps);
            break;
          case 'aes-256':
            processedData = await encryptAES(input, key, 256, processingSteps);
            break;
          case 'des':
            processedData = await encryptDES(input, key, processingSteps);
            break;
          case 'chacha20':
            processedData = await encryptChaCha20(input, key, processingSteps);
            break;
          default:
            processedData = '';
        }
      } else {
        // Decryption based on selected algorithm
        switch (algorithm) {
          case 'aes-128':
            processedData = await decryptAES(input, key, 128, processingSteps);
            break;
          case 'aes-256':
            processedData = await decryptAES(input, key, 256, processingSteps);
            break;
          case 'des':
            processedData = await decryptDES(input, key, processingSteps);
            break;
          case 'chacha20':
            processedData = await decryptChaCha20(input, key, processingSteps);
            break;
          default:
            processedData = '';
        }
      }
      
      setResult(processedData);
      setSteps(processingSteps);
    } catch (error) {
      console.error('Processing error:', error);
      alert(`Error: ${error.message}`);
    }
    
    setLoading(false);
  };
  
  /**
   * Saves the ciphertext to a file
   */
  const handleSaveCiphertext = () => {
    if (result) {
      saveToFile(result, mode === 'encrypt' ? 'ciphertext.txt' : 'plaintext.txt');
    }
  };
  
  /**
   * Saves the key to a file
   */
  const handleSaveKey = () => {
    if (key) {
      saveToFile(key, 'encryption.key');
    }
  };
  
  /**
   * Loads a key from a file
   */
  const handleLoadKey = async (e) => {
    try {
      const fileKey = await loadFromFile(e);
      setKey(fileKey.trim());
    } catch (error) {
      console.error('Error loading key:', error);
      alert('Error loading key file');
    }
  };
  
  return (
    <div className="encryption-form">
      {/* Mode Selection */}
      <div className="form-section">
        <h2>Operation Mode</h2>
        <div className="radio-group">
          <label>
            <input
              type="radio"
              value="encrypt"
              checked={mode === 'encrypt'}
              onChange={() => setMode('encrypt')}
            />
            Encrypt
          </label>
          <label>
            <input
              type="radio"
              value="decrypt"
              checked={mode === 'decrypt'}
              onChange={() => setMode('decrypt')}
            />
            Decrypt
          </label>
        </div>
      </div>
      
      {/* Algorithm Selection - show only for encryption */}
      {mode === 'encrypt' && (
        <div className="form-section">
          <h2>Algorithm</h2>
          <select 
            value={algorithm} 
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            <option value="aes-128">AES (128-bit)</option>
            <option value="aes-256">AES (256-bit)</option>
            <option value="des">DES</option>
            <option value="chacha20">ChaCha20</option>
          </select>
        </div>
      )}
      
      {/* Input Type Selection - show only for encryption */}
      {mode === 'encrypt' && (
        <div className="form-section">
          <h2>Input Type</h2>
          <div className="radio-group">
            <label>
              <input
                type="radio"
                value="text"
                checked={inputType === 'text'}
                onChange={() => setInputType('text')}
              />
              Text
            </label>
            <label>
              <input
                type="radio"
                value="password"
                checked={inputType === 'password'}
                onChange={() => setInputType('password')}
              />
              Password
            </label>
          </div>
        </div>
      )}
      
      {/* Input Field */}
      <div className="form-section">
        <h2>{mode === 'encrypt' ? 'Input' : 'Ciphertext'}</h2>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={mode === 'encrypt' 
            ? (inputType === 'text' ? 'Enter text to encrypt' : 'Enter password')
            : 'Enter ciphertext (hex format) to decrypt'}
        />
      </div>
      
      {/* Key Section */}
      <div className="form-section">
        <h2>Encryption Key</h2>
        <input
          type="text"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Encryption key (hexadecimal format)"
        />
        <div className="button-group">
          <button 
            onClick={handleGenerateKey}
            disabled={loading}
          >
            Generate Random Key
          </button>
          
          {mode === 'encrypt' && inputType === 'password' && (
            <button 
              onClick={handleDeriveKey}
              disabled={loading || !input}
            >
              Derive Key from Password
            </button>
          )}
          
          {mode === 'encrypt' && (
            <button 
              onClick={handleSaveKey}
              disabled={loading || !key}
            >
              Save Key
            </button>
          )}
          
          {mode === 'decrypt' && (
            <div className="file-input-wrapper">
              <label className="file-input-label">
                Upload Key File
                <input 
                  type="file" 
                  onChange={handleLoadKey}
                  disabled={loading}
                />
              </label>
            </div>
          )}
        </div>
      </div>
      
      {/* Process Button */}
      <div className="form-section">
        <button 
          className="process-button" 
          onClick={handleProcess}
          disabled={loading || !input || !key}
        >
          {loading ? 'Processing...' : mode === 'encrypt' ? 'Encrypt' : 'Decrypt'}
        </button>
      </div>
      
      {/* Result Section */}
      {result && (
        <div className="form-section">
          <h2>Result</h2>
          <textarea 
            value={result} 
            readOnly 
          />
          <button 
            onClick={handleSaveCiphertext}
            disabled={loading}
          >
            Save to File
          </button>
        </div>
      )}
      
      {/* Steps Visualization */}
      {steps.length > 0 && (
        <div className="form-section">
          <h2>Process Visualization</h2>
          <div className="steps-container">
            {steps.map((step, index) => (
              <div key={index} className="step-item">
                <h3>{step.title}</h3>
                <div className="step-visualization">
                  <div className="step-hex">
                    <h4>Hexadecimal</h4>
                    <pre>{step.hex}</pre>
                  </div>
                  <div className="step-binary">
                    <h4>Binary</h4>
                    <pre>{step.binary}</pre>
                  </div>
                </div>
                <p className="step-description">{step.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default EncryptionForm;
