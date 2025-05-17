const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour détecter les problèmes de protection CSRF
const csrfPatterns = [
  {
    type: 'Absence de middleware CSRF',
    pattern: /app\.use\(\s*(?!.*csrf)/i,
    severity: 'HIGH',
    solution: 'Utilisez csurf ou un autre middleware de protection CSRF'
  },
  {
    type: 'Routes POST sans protection CSRF',
    pattern: /app\.post\(\s*['"`][^'"`]+['"`]\s*,\s*(?!.*csrf)/i,
    severity: 'HIGH',
    solution: 'Assurez-vous que toutes les routes POST sont protégées par un middleware CSRF'
  },
  {
    type: 'Routes PUT sans protection CSRF',
    pattern: /app\.put\(\s*['"`][^'"`]+['"`]\s*,\s*(?!.*csrf)/i,
    severity: 'HIGH',
    solution: 'Assurez-vous que toutes les routes PUT sont protégées par un middleware CSRF'
  },
  {
    type: 'Routes DELETE sans protection CSRF',
    pattern: /app\.delete\(\s*['"`][^'"`]+['"`]\s*,\s*(?!.*csrf)/i,
    severity: 'HIGH',
    solution: 'Assurez-vous que toutes les routes DELETE sont protégées par un middleware CSRF'
  },
  {
    type: 'Utilisation de fetch sans CSRF token',
    pattern: /fetch\(\s*['"`][^'"`]+['"`]\s*,\s*\{\s*method\s*:\s*['"`](POST|PUT|DELETE|PATCH)['"`]/i,
    severity: 'MEDIUM',
    solution: 'Ajoutez un header CSRF-Token aux requêtes fetch mutantes'
  },
  {
    type: 'Utilisation d\'axios sans CSRF token',
    pattern: /axios\.(post|put|delete|patch)\(/i,
    severity: 'MEDIUM',
    solution: 'Configurez axios pour inclure un header CSRF-Token dans toutes les requêtes mutantes'
  }
];

// Bonnes pratiques pour la protection CSRF
const csrfBestPractices = [
  {
    name: 'csurf',
    description: 'Middleware de protection CSRF pour Express'
  },
  {
    name: 'double-submit-cookie',
    description: 'Utiliser la technique du double submit cookie en envoyant le même token dans un cookie et dans un header'
  },
  {
    name: 'SameSite',
    description: 'Utiliser l\'attribut SameSite=Strict pour les cookies de session'
  },
  {
    name: 'X-CSRF-Token',
    description: 'Vérifier la présence d\'un header X-CSRF-Token dans toutes les requêtes mutantes'
  }
];

exports.scanCSRF = (projectPath) => {
  const csrfIssues = [];
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Vérifier les problèmes de protection CSRF
  for (const pattern of csrfPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      csrfIssues.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier si csurf est installé
  const packageJson = parsePackageJson(projectPath);
  let csurfInstalled = false;
  let helmetInstalled = false;
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    csurfInstalled = dependencies && dependencies['csurf'];
    helmetInstalled = dependencies && dependencies['helmet'];
  }
  
  // Vérifier si helmet est configuré correctement (pour SameSite cookies)
  let helmetConfigured = false;
  if (helmetInstalled) {
    const helmetResults = findFilesWithPattern(projectPath, filePattern, /helmet\(\s*\{/i);
    helmetConfigured = helmetResults.length > 0;
  }
  
  // Vérifier la présence d'utilisation de tokens CSRF
  const csrfTokenUsage = findFilesWithPattern(projectPath, filePattern, /(csrf[tT]oken|CSRF[_\-]TOKEN)/i);
  
  return {
    issues: csrfIssues,
    protection: {
      csurfInstalled,
      helmetInstalled,
      helmetConfigured,
      csrfTokensUsed: csrfTokenUsage.length > 0
    },
    bestPractices: csrfBestPractices,
    total: csrfIssues.length
  };
}; 