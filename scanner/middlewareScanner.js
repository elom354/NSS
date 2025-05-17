const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Middlewares de sécurité essentiels
const securityMiddlewares = [
  {
    name: 'helmet',
    description: 'Ajoute diverses en-têtes HTTP de sécurité',
    priority: 'HIGH',
    npm: 'helmet'
  },
  {
    name: 'cors',
    description: 'Configure les règles de partage de ressources cross-origin',
    priority: 'HIGH',
    npm: 'cors'
  },
  {
    name: 'express-rate-limit',
    description: 'Limite le nombre de requêtes pour prévenir les attaques par force brute',
    priority: 'HIGH',
    npm: 'express-rate-limit'
  },
  {
    name: 'csurf',
    description: 'Protection contre les attaques CSRF',
    priority: 'HIGH',
    npm: 'csurf'
  },
  {
    name: 'express-validator',
    description: 'Validation et sanitization des entrées utilisateur',
    priority: 'HIGH',
    npm: 'express-validator'
  },
  {
    name: 'xss-clean',
    description: 'Nettoie les entrées utilisateur des scripts malveillants',
    priority: 'HIGH',
    npm: 'xss-clean'
  },
  {
    name: 'hpp',
    description: 'Protection contre la pollution des paramètres HTTP',
    priority: 'MEDIUM',
    npm: 'hpp'
  },
  {
    name: 'sanitize-html',
    description: 'Nettoie le HTML des scripts et attributs malveillants',
    priority: 'MEDIUM',
    npm: 'sanitize-html'
  },
  {
    name: 'cookie-parser',
    description: 'Analye les cookies et les met à disposition dans req.cookies',
    priority: 'MEDIUM',
    npm: 'cookie-parser'
  },
  {
    name: 'express-session',
    description: 'Gestion des sessions avec Express',
    priority: 'MEDIUM',
    npm: 'express-session'
  },
  {
    name: 'express-mongo-sanitize',
    description: 'Prévient les injections NoSQL MongoDB',
    priority: 'MEDIUM',
    npm: 'express-mongo-sanitize'
  },
  {
    name: 'content-security-policy',
    description: 'Définit des politiques CSP pour prévenir diverses attaques',
    priority: 'MEDIUM',
    npm: 'helmet ou csp'
  },
  {
    name: 'compression',
    description: 'Compresse les réponses HTTP',
    priority: 'LOW',
    npm: 'compression'
  },
  {
    name: 'express-fileupload',
    description: 'Sécurise le téléchargement de fichiers',
    priority: 'LOW',
    npm: 'express-fileupload'
  },
  {
    name: 'timeout',
    description: 'Définit un délai d\'expiration pour les requêtes',
    priority: 'LOW',
    npm: 'connect-timeout'
  }
];

// Motifs pour détecter l'utilisation de middlewares
const middlewarePatterns = [
  {
    name: 'helmet',
    pattern: /app\.use\(\s*(helmet|require\(['"]helmet['"]\))\s*\(/i
  },
  {
    name: 'cors',
    pattern: /app\.use\(\s*(cors|require\(['"]cors['"]\))\s*\(/i
  },
  {
    name: 'express-rate-limit',
    pattern: /(rateLimit|rateLimiter|limiter)\s*=\s*require\(['"]express-rate-limit['"]|app\.use\(\s*rateLimit/i
  },
  {
    name: 'csurf',
    pattern: /app\.use\(\s*(csrf|csurf|require\(['"]csurf['"]\))\s*\(/i
  },
  {
    name: 'express-validator',
    pattern: /require\(['"]express-validator['"]|check|body|validationResult/i
  },
  {
    name: 'xss-clean',
    pattern: /app\.use\(\s*(xss|require\(['"]xss-clean['"]\))\s*\(/i
  },
  {
    name: 'hpp',
    pattern: /app\.use\(\s*(hpp|require\(['"]hpp['"]\))\s*\(/i
  },
  {
    name: 'sanitize-html',
    pattern: /require\(['"]sanitize-html['"]|sanitizeHtml/i
  },
  {
    name: 'express-mongo-sanitize',
    pattern: /app\.use\(\s*(mongoSanitize|require\(['"]express-mongo-sanitize['"]\))\s*\(/i
  },
  {
    name: 'content-security-policy',
    pattern: /helmet\([^)]*\{\s*contentSecurityPolicy/i
  },
  {
    name: 'compression',
    pattern: /app\.use\(\s*(compression|require\(['"]compression['"]\))\s*\(/i
  }
];

// Vérifier les configurations potentiellement incorrectes
const middlewareConfigPatterns = [
  {
    name: 'CORS Permissif',
    pattern: /cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/i,
    severity: 'HIGH',
    solution: 'Limitez les origines CORS à des domaines spécifiques plutôt que d\'utiliser *'
  },
  {
    name: 'Rate Limit Faible',
    pattern: /rateLimit\(\s*\{\s*(?:[^}]*\s*,\s*)?max\s*:\s*(\d+)/i,
    severity: 'MEDIUM',
    solution: 'Définissez une limite de requêtes plus restrictive (max < 100)'
  },
  {
    name: 'Helmet sans CSP',
    pattern: /helmet\(\s*\{\s*contentSecurityPolicy\s*:\s*false/i,
    severity: 'MEDIUM',
    solution: 'Activez la politique de sécurité du contenu (CSP) dans helmet'
  }
];

exports.scanMiddlewares = (projectPath) => {
  // Analyser le package.json pour trouver les dépendances installées
  const packageJson = parsePackageJson(projectPath);
  const installedPackages = [];
  const missingPackages = [];
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const middleware of securityMiddlewares) {
      if (dependencies && dependencies[middleware.npm]) {
        installedPackages.push(middleware);
      } else {
        missingPackages.push(middleware);
      }
    }
  }
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Rechercher l'utilisation des middlewares dans le code
  const usedMiddlewares = [];
  
  for (const pattern of middlewarePatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    if (results.length > 0) {
      usedMiddlewares.push({
        name: pattern.name,
        files: results.map(r => ({ file: r.file, line: r.line }))
      });
    }
  }
  
  // Vérifier les configurations incorrectes
  const configurationIssues = [];
  
  for (const pattern of middlewareConfigPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      configurationIssues.push({
        file: result.file,
        line: result.line,
        name: pattern.name,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Analyser express-session configuration
  let sessionAnalysis = null;
  if (installedPackages.some(m => m.name === 'express-session')) {
    const sessionResults = findFilesWithPattern(projectPath, filePattern, /session\(\s*\{/i);
    
    if (sessionResults.length > 0) {
      const sessionResult = sessionResults[0];
      const httpOnlyMissing = !sessionResult.context.includes('httpOnly: true');
      const secureMissing = !sessionResult.context.includes('secure: true');
      const sameSiteMissing = !sessionResult.context.includes('sameSite');
      
      sessionAnalysis = {
        file: sessionResult.file,
        line: sessionResult.line,
        issues: []
      };
      
      if (httpOnlyMissing) {
        sessionAnalysis.issues.push('httpOnly manquant dans la configuration de session');
      }
      
      if (secureMissing) {
        sessionAnalysis.issues.push('secure manquant dans la configuration de session');
      }
      
      if (sameSiteMissing) {
        sessionAnalysis.issues.push('sameSite manquant dans la configuration de session');
      }
    }
  }
  
  return {
    installed: {
      packages: installedPackages.map(m => ({ name: m.name, description: m.description })),
      count: installedPackages.length
    },
    missing: {
      packages: missingPackages
        .filter(m => m.priority === 'HIGH')
        .map(m => ({ name: m.name, description: m.description, npm: m.npm })),
      count: missingPackages.filter(m => m.priority === 'HIGH').length
    },
    recommended: {
      packages: missingPackages
        .filter(m => m.priority === 'MEDIUM')
        .map(m => ({ name: m.name, description: m.description, npm: m.npm })),
      count: missingPackages.filter(m => m.priority === 'MEDIUM').length
    },
    used: {
      middlewares: usedMiddlewares,
      count: usedMiddlewares.length
    },
    configurationIssues,
    sessionAnalysis,
    securityScore: calculateSecurityScore(installedPackages, missingPackages, configurationIssues.length)
  };
};

/**
 * Calcule un score de sécurité basé sur les middlewares installés
 * @param {Array} installed - Middlewares installés
 * @param {Array} missing - Middlewares manquants
 * @param {number} configIssues - Nombre de problèmes de configuration
 * @returns {number} - Score de sécurité (0-100)
 */
function calculateSecurityScore(installed, missing, configIssues) {
  let score = 100;
  
  // Déduire des points pour les middlewares essentiels manquants
  const missingHighPriority = missing.filter(m => m.priority === 'HIGH').length;
  score -= (missingHighPriority * 15);
  
  // Déduire des points pour les middlewares recommandés manquants
  const missingMediumPriority = missing.filter(m => m.priority === 'MEDIUM').length;
  score -= (missingMediumPriority * 5);
  
  // Déduire des points pour les problèmes de configuration
  score -= (configIssues * 10);
  
  // Limiter le score à 0-100
  return Math.max(0, Math.min(100, score));
}
