const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour détecter les problèmes d'authentification
const authPatterns = [
  {
    type: 'Mot de passe en clair',
    pattern: /\.(compare|matches?)\(\s*('|"|`)?password('|"|`)?\s*,/i,
    severity: 'HIGH',
    solution: 'Utilisez bcrypt, argon2 ou scrypt pour hacher les mots de passe'
  },
  {
    type: 'Session non sécurisée',
    pattern: /app\.use\(\s*session\(\s*\{\s*(?!.*secure:.*true).*\}\s*\)\s*\)/i,
    severity: 'MEDIUM',
    solution: 'Définissez l\'option secure: true pour les sessions en production'
  },
  {
    type: 'Session avec cookie httpOnly manquant',
    pattern: /app\.use\(\s*session\(\s*\{\s*(?!.*httpOnly:.*true).*\}\s*\)\s*\)/i,
    severity: 'MEDIUM',
    solution: 'Définissez l\'option httpOnly: true pour les cookies de session'
  },
  {
    type: 'JWT non vérifié',
    pattern: /jwt\.sign\(/i,
    severity: 'LOW',
    solution: 'Assurez-vous de vérifier les tokens JWT avec jwt.verify()'
  },
  {
    type: 'Clé secrète JWT faible',
    pattern: /jwt\.sign\([^,]+,\s*['"`][a-zA-Z0-9]{1,32}['"`]/i,
    severity: 'HIGH',
    solution: 'Utilisez une clé secrète JWT forte (min. 32 caractères) stockée dans les variables d\'environnement'
  },
  {
    type: 'Expiration manquante',
    pattern: /jwt\.sign\([^)]*\)\s*;/i,
    severity: 'MEDIUM',
    solution: 'Ajoutez une option expiresIn pour définir une expiration des tokens JWT'
  },
  {
    type: 'JWT sans validation',
    pattern: /jwt\.decode\(/i,
    severity: 'HIGH',
    solution: 'Utilisez jwt.verify() au lieu de jwt.decode() pour valider les signatures'
  },
  {
    type: 'Authentification personnalisée',
    pattern: /function\s+(authenticate|login|signIn|check[A-Z][a-z]*Auth|isAuth)/i,
    severity: 'LOW',
    solution: 'Envisagez d\'utiliser une bibliothèque d\'authentification éprouvée comme Passport.js'
  },
  {
    type: 'Authentification sans vérification de rôle',
    pattern: /req\.(user|currentUser|auth)\.role/i,
    severity: 'INFO',
    solution: 'Vérifiez que vous validez correctement les rôles d\'utilisateur pour l\'autorisation'
  }
];

// Motifs pour détecter les problèmes d'autorisation
const authorizationPatterns = [
  {
    type: 'Absence de vérification d\'autorisation',
    pattern: /app\.(get|post|put|delete|patch)\(\s*['"`][^'"`]+['"`]\s*,\s*(?!.*auth).*function/i,
    severity: 'MEDIUM',
    solution: 'Ajoutez un middleware d\'authentification pour les routes sensibles'
  },
  {
    type: 'API ouverte',
    pattern: /app\.(get|post|put|delete|patch)\(\s*['"`]\/api\/[^'"`]+['"`]\s*,\s*(?!.*auth).*function/i,
    severity: 'HIGH',
    solution: 'Protégez vos endpoints API avec un middleware d\'authentification'
  },
  {
    type: 'Autorisations insuffisantes',
    pattern: /\b(isAuth|isAuthenticated|authenticate|requireAuth)\b\s*\([^)]*\)/i,
    severity: 'INFO',
    solution: 'Vérifiez si vous contrôlez également les autorisations (rôles) et pas seulement l\'authentification'
  },
  {
    type: 'Autorisations de base',
    pattern: /req\.(user|currentUser)\.role\s*===\s*['"`](admin|superuser)['"`]/i,
    severity: 'LOW',
    solution: 'Envisagez d\'utiliser un système d\'autorisation basé sur les capacités ou RBAC plus avancé'
  }
];

const recommendedPackages = [
  'bcrypt',
  'argon2',
  'jsonwebtoken',
  'passport',
  'express-jwt',
  'helmet',
  'express-rate-limit',
  'express-validator',
  'accesscontrol',
  'casl'
];

exports.scanAuthentication = (projectPath) => {
  const authIssues = [];
  const authorizationIssues = [];
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Vérifier les problèmes d'authentification
  for (const pattern of authPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      authIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les problèmes d'autorisation
  for (const pattern of authorizationPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      authorizationIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les packages de sécurité installés
  const packageJson = parsePackageJson(projectPath);
  const installedPackages = [];
  const missingPackages = [];
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const pkg of recommendedPackages) {
      if (dependencies && dependencies[pkg]) {
        installedPackages.push(pkg);
      } else {
        missingPackages.push(pkg);
      }
    }
  }
  
  return {
    auth: authIssues,
    authorization: authorizationIssues,
    packages: {
      installed: installedPackages,
      recommended: missingPackages
    },
    total: authIssues.length + authorizationIssues.length
  };
}; 