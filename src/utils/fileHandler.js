/**
 * File handling utilities for saving and loading cryptographic data
 */

/**
 * Saves data to a file and triggers a download
 * @param {string} data - The data to save
 * @param {string} filename - The name of the file
 */
export const saveToFile = (data, filename) => {
  // Create a blob with the data
  const blob = new Blob([data], { type: 'text/plain' });
  
  // Create a URL for the blob
  const url = URL.createObjectURL(blob);
  
  // Create a temporary anchor element
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  
  // Append to the document
  document.body.appendChild(link);
  
  // Trigger download
  link.click();
  
  // Clean up
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

/**
 * Loads data from a file
 * @param {Event} event - File input change event
 * @returns {Promise<string>} - The file contents
 */
export const loadFromFile = (event) => {
  return new Promise((resolve, reject) => {
    const file = event.target.files[0];
    
    if (!file) {
      reject(new Error('No file selected'));
      return;
    }
    
    const reader = new FileReader();
    
    reader.onload = (e) => {
      resolve(e.target.result);
    };
    
    reader.onerror = () => {
      reject(new Error('Error reading file'));
    };
    
    reader.readAsText(file);
  });
};
