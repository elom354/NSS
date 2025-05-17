const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour détecter les problèmes de sécurité liés aux cookies
const cookiePatterns = [
  {
    type: 'Cookie sans httpOnly',
    pattern: /cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+\s*,\s*\{\s*(?!.*httpOnly:.*true).*\}/i,
    severity: 'HIGH',
    solution: 'Définissez l\'option httpOnly: true pour empêcher l\'accès aux cookies via JavaScript'
  },
  {
    type: 'Cookie sans secure',
    pattern: /cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+\s*,\s*\{\s*(?!.*secure:.*true).*\}/i,
    severity: 'HIGH',
    solution: 'Définissez l\'option secure: true pour que les cookies ne soient envoyés que via HTTPS'
  },
  {
    type: 'Cookie sans sameSite',
    pattern: /cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+\s*,\s*\{\s*(?!.*sameSite).*\}/i,
    severity: 'MEDIUM',
    solution: 'Définissez l\'option sameSite: \'strict\' ou \'lax\' pour prévenir les attaques CSRF'
  },
  {
    type: 'Cookie avec expiration longue',
    pattern: /cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+\s*,\s*\{\s*maxAge\s*:\s*(\d{8,})/i,
    severity: 'MEDIUM',
    solution: 'Réduisez la durée de vie des cookies sensibles (maxAge inférieur à 86400000 pour les sessions)'
  },
  {
    type: 'Cookie avec domain trop permissif',
    pattern: /cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+\s*,\s*\{\s*domain\s*:\s*['"`]\.[^'"`]+['"`]/i,
    severity: 'MEDIUM',
    solution: 'Évitez d\'utiliser un domaine commençant par un point (.example.com) qui permet tous les sous-domaines'
  },
  {
    type: 'Cookie session sans configuration sécurisée',
    pattern: /session\(\s*\{\s*(?!.*cookie:.*httpOnly:.*true).*\}\s*\)/i,
    severity: 'HIGH',
    solution: 'Configurez les cookies de session avec httpOnly: true, secure: true et sameSite: \'strict\''
  }
];

// Motifs pour détecter la gestion de cookies
const cookieManagementPatterns = [
  {
    type: 'Utilisation de document.cookie',
    pattern: /document\.cookie\s*=/i,
    severity: 'MEDIUM',
    solution: 'Utilisez une bibliothèque de gestion de cookies ou les API de stockage du navigateur'
  },
  {
    type: 'Cookie localStorage',
    pattern: /localStorage\.setItem\(\s*['"`][^'"`]*token[^'"`]*['"`]/i,
    severity: 'HIGH',
    solution: 'Ne stockez pas de tokens d\'authentification dans localStorage, utilisez des cookies httpOnly'
  },
  {
    type: 'Stockage sessionStorage',
    pattern: /sessionStorage\.setItem\(\s*['"`][^'"`]*token[^'"`]*['"`]/i,
    severity: 'MEDIUM', 
    solution: 'Préférez les cookies httpOnly aux tokens stockés dans sessionStorage'
  }
];

const cookieManagementPackages = [
  'cookie-parser',
  'cookie-session',
  'express-session',
  'js-cookie',
  'universal-cookie'
];

exports.scanCookies = (projectPath) => {
  const cookieIssues = [];
  const cookieManagementIssues = [];
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Vérifier les problèmes de sécurité liés aux cookies
  for (const pattern of cookiePatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      cookieIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les problèmes de gestion de cookies
  for (const pattern of cookieManagementPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      cookieManagementIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les packages de gestion de cookies installés
  const packageJson = parsePackageJson(projectPath);
  const installedPackages = [];
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const pkg of cookieManagementPackages) {
      if (dependencies && dependencies[pkg]) {
        installedPackages.push(pkg);
      }
    }
  }
  
  // Détection des configurations de cookie-parser ou express-session
  let cookieParserConfig = null;
  let sessionConfig = null;
  
  if (installedPackages.includes('cookie-parser')) {
    const cookieParserResults = findFilesWithPattern(projectPath, filePattern, /app\.use\(\s*cookieParser\(/i);
    if (cookieParserResults.length > 0) {
      cookieParserConfig = cookieParserResults[0].context;
    }
  }
  
  if (installedPackages.includes('express-session')) {
    const sessionResults = findFilesWithPattern(projectPath, filePattern, /app\.use\(\s*session\(\s*\{/i);
    if (sessionResults.length > 0) {
      sessionConfig = sessionResults[0].context;
    }
  }
  
  return {
    cookies: cookieIssues,
    management: cookieManagementIssues,
    packages: {
      installed: installedPackages
    },
    configurations: {
      cookieParser: cookieParserConfig,
      session: sessionConfig
    },
    bestPractices: [
      'Utilisez toujours l\'attribut httpOnly pour les cookies sensibles',
      'Activez l\'attribut secure en production',
      'Définissez sameSite à \'strict\' ou \'lax\'',
      'Limitez la durée de vie des cookies d\'authentification',
      'Préférez les cookies httpOnly au stockage localStorage/sessionStorage pour les tokens',
      'Définissez une politique de cookies claire'
    ],
    total: cookieIssues.length + cookieManagementIssues.length
  };
}; 