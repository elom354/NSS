const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour détecter les problèmes de validation d'entrée
const inputValidationPatterns = [
  {
    type: 'Absence de validation',
    pattern: /req\.(body|params|query)\.([a-zA-Z0-9_]+)/i,
    severity: 'MEDIUM',
    solution: 'Validez les entrées utilisateur avec express-validator, Joi ou un autre validateur'
  },
  {
    type: 'Entrée utilisateur directe',
    pattern: /(eval|Function|setTimeout|setInterval)\s*\(\s*req\.(body|params|query)/i,
    severity: 'CRITICAL',
    solution: 'N\'exécutez jamais de code provenant des entrées utilisateur'
  },
  {
    type: 'Déstructuration sans validation',
    pattern: /const\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(body|params|query)/i,
    severity: 'LOW',
    solution: 'Validez les entrées avant de les déstructurer'
  },
  {
    type: 'Absence de sanitization',
    pattern: /innerHTML\s*=\s*.*req\.(body|params|query)/i,
    severity: 'HIGH',
    solution: 'Utilisez sanitize-html ou DOMPurify pour nettoyer le HTML'
  },
  {
    type: 'Requête dynamique avec entrée utilisateur',
    pattern: /db\.query\s*\(\s*.*req\.(body|params|query)/i,
    severity: 'HIGH',
    solution: 'Utilisez des requêtes préparées et validez les entrées utilisateur'
  }
];

// Motifs pour détecter les vulnérabilités XSS
const xssPatterns = [
  {
    type: 'Potentielle vulnérabilité XSS',
    pattern: /innerHTML\s*=|document\.write\s*\(/i,
    severity: 'HIGH',
    solution: 'Utilisez textContent ou innerText, ou sanitize-html pour nettoyer le contenu HTML'
  },
  {
    type: 'Potentielle vulnérabilité XSS avec entrées utilisateur',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/i,
    severity: 'MEDIUM',
    solution: 'Assurez-vous de nettoyer les entrées utilisateur avant d\'utiliser dangerouslySetInnerHTML dans React'
  },
  {
    type: 'Absence d\'échappement HTML',
    pattern: /\.send\s*\(\s*.*req\.(body|params|query)/i,
    severity: 'MEDIUM',
    solution: 'Échappez le contenu HTML ou utilisez des bibliothèques de templates qui échappent automatiquement'
  }
];

// Motifs pour détecter les problèmes de type
const typeValidationPatterns = [
  {
    type: 'Conversion de type non sécurisée',
    pattern: /parseInt\s*\(\s*req\.(body|params|query)/i,
    severity: 'LOW',
    solution: 'Utilisez parseInt avec une base explicite (par exemple parseInt(value, 10))'
  },
  {
    type: 'Vérification de type faible',
    pattern: /==\s*null|null\s*==/i,
    severity: 'LOW',
    solution: 'Utilisez l\'opérateur d\'égalité stricte (===) au lieu de l\'égalité faible (==)'
  }
];

const recommendedValidationPackages = [
  'express-validator',
  'joi',
  'yup',
  'ajv',
  'validator',
  'zod',
  'sanitize-html',
  'dompurify',
  'xss'
];

exports.scanInputValidation = (projectPath) => {
  const validationIssues = [];
  const xssIssues = [];
  const typeIssues = [];
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Vérifier les problèmes de validation d'entrée
  for (const pattern of inputValidationPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      validationIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les vulnérabilités XSS
  for (const pattern of xssPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      xssIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les problèmes de type
  for (const pattern of typeValidationPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      typeIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les packages de validation installés
  const packageJson = parsePackageJson(projectPath);
  const installedPackages = [];
  const missingPackages = [];
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const pkg of recommendedValidationPackages) {
      if (dependencies && dependencies[pkg]) {
        installedPackages.push(pkg);
      } else {
        missingPackages.push(pkg);
      }
    }
  }
  
  return {
    validation: validationIssues,
    xss: xssIssues,
    typeErrors: typeIssues,
    packages: {
      installed: installedPackages,
      recommended: missingPackages
    },
    total: validationIssues.length + xssIssues.length + typeIssues.length
  };
}; 