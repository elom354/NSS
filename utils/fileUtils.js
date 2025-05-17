const fs = require('fs');
const path = require('path');
const glob = require('glob');

/**
 * Trouve tous les fichiers correspondant au motif dans le répertoire cible
 * @param {string} projectPath - Chemin du projet
 * @param {string} pattern - Motif globby (exemple: "src/js/*.js")
 * @returns {string[]} - Liste des chemins de fichiers
 */
exports.findFiles = (projectPath, pattern) => {
  return glob.sync(path.join(projectPath, pattern));
};

/**
 * Lit le contenu d'un fichier
 * @param {string} filePath - Chemin du fichier
 * @returns {string} - Contenu du fichier
 */
exports.readFileContent = (filePath) => {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch (error) {
    console.error(`Erreur lors de la lecture du fichier ${filePath}:`, error.message);
    return '';
  }
};

/**
 * Vérifie si un motif existe dans un fichier
 * @param {string} filePath - Chemin du fichier
 * @param {RegExp|string} pattern - Motif à rechercher
 * @returns {boolean} - True si le motif est trouvé
 */
exports.fileContainsPattern = (filePath, pattern) => {
  const content = exports.readFileContent(filePath);
  if (typeof pattern === 'string') {
    return content.includes(pattern);
  }
  return pattern.test(content);
};

/**
 * Trouve tous les fichiers contenant un motif
 * @param {string} projectPath - Chemin du projet
 * @param {string} filePattern - Motif de fichier (exemple: "src/js/*.js")
 * @param {RegExp|string} contentPattern - Motif de contenu
 * @returns {Object[]} - Liste des fichiers avec leurs chemins et le contexte
 */
exports.findFilesWithPattern = (projectPath, filePattern, contentPattern) => {
  const files = exports.findFiles(projectPath, filePattern);
  const matches = [];

  for (const file of files) {
    const content = exports.readFileContent(file);
    const relativePath = path.relative(projectPath, file);
    
    if (typeof contentPattern === 'string') {
      if (content.includes(contentPattern)) {
        const lines = content.split('\n');
        const lineNumber = lines.findIndex(line => line.includes(contentPattern));
        matches.push({
          file: relativePath,
          line: lineNumber >= 0 ? lineNumber + 1 : null,
          context: lineNumber >= 0 ? lines[lineNumber] : null
        });
      }
    } else if (contentPattern instanceof RegExp) {
      const match = content.match(contentPattern);
      if (match) {
        const lines = content.split('\n');
        const matchedText = match[0];
        const lineNumber = lines.findIndex(line => line.includes(matchedText));
        matches.push({
          file: relativePath,
          line: lineNumber >= 0 ? lineNumber + 1 : null,
          context: lineNumber >= 0 ? lines[lineNumber].trim() : null
        });
      }
    }
  }

  return matches;
};

/**
 * Parse le package.json d'un projet
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Contenu du package.json
 */
exports.parsePackageJson = (projectPath) => {
  try {
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      return JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    }
    return null;
  } catch (error) {
    console.error('Erreur lors de l\'analyse du package.json:', error.message);
    return null;
  }
};
