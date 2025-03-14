import React from 'react';
import EncryptionForm from './components/EncryptionForm';
import './App.css';

/**
 * Main application component for the encryption learning tool
 * Serves as the container for the entire application
 */
function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Encryption Learning Tool</h1>
        <p>Interactive visualisation of DES, AES, and CHACHA20 encryption algorithms</p>
		<i>Do not actually enter your password into this tool</i>
      </header>
      <main>
        <EncryptionForm />
      </main>
      <footer>
        <p>Created for educational purposes to help visualize encryption algorithms</p>
      </footer>
    </div>
  );
}

export default App;
