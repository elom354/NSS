const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour la détection de rate limiting
const rateLimitPatterns = [
  {
    name: 'express-rate-limit',
    pattern: /require\(['"]express-rate-limit['"]|import\s+.*\s+from\s+['"]express-rate-limit['"]/i
  },
  {
    name: 'rate-limiter-flexible',
    pattern: /require\(['"]rate-limiter-flexible['"]|import\s+.*\s+from\s+['"]rate-limiter-flexible['"]/i
  },
  {
    name: 'express-brute',
    pattern: /require\(['"]express-brute['"]|import\s+.*\s+from\s+['"]express-brute['"]/i
  },
  {
    name: 'node-rate-limiter',
    pattern: /require\(['"]node-rate-limiter['"]|import\s+.*\s+from\s+['"]node-rate-limiter['"]/i
  },
  {
    name: 'rate-limit-redis',
    pattern: /require\(['"]rate-limit-redis['"]|import\s+.*\s+from\s+['"]rate-limit-redis['"]/i
  },
  {
    name: 'custom-rate-limiter',
    pattern: /function\s+(rateLimit|rateLimiter|limiter)/i
  }
];

// Motifs pour détecter les problèmes de configuration de rate limiting
const rateLimitConfigPatterns = [
  {
    name: 'Limite de taux faible',
    pattern: /rateLimit\(\s*\{\s*(?:[^}]*\s*,\s*)?max\s*:\s*(\d+)/i,
    severity: 'MEDIUM', 
    solution: 'Réduisez la valeur max pour les endpoints sensibles à moins de 100 requêtes',
    threshold: 100
  },
  {
    name: 'Fenêtre de temps de limite courte',
    pattern: /rateLimit\(\s*\{\s*(?:[^}]*\s*,\s*)?windowMs\s*:\s*(\d+)/i,
    severity: 'LOW',
    solution: 'Augmentez la durée de la fenêtre de temps (windowMs) pour une meilleure protection',
    threshold: 60000 // 1 minute
  },
  {
    name: 'Absence de message d\'erreur',
    pattern: /rateLimit\(\s*\{\s*(?![^}]*message:)/i,
    severity: 'LOW',
    solution: 'Ajoutez un message d\'erreur personnalisé pour informer les utilisateurs de la limitation'
  }
];

// Endpoints sensibles qui devraient avoir une limite de taux
const sensitivePaths = [
  '/login',
  '/signin',
  '/register',
  '/signup',
  '/auth',
  '/reset-password',
  '/forgot-password',
  '/api/auth',
  '/api/login',
  '/api/signup'
];

// Rate limiter recommandé
const recommendedRateLimiter = `
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requêtes par IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Trop de requêtes, veuillez réessayer plus tard'
});

// Protection de force brute pour l'authentification
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 5, // 5 tentatives par IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Trop de tentatives de connexion, veuillez réessayer dans une heure'
});

// Appliquer les limiteurs
app.use(globalLimiter); // Limiter global
app.use('/api/auth/login', loginLimiter); // Limiter spécifique à l'authentification
`;

exports.scanRateLimit = (projectPath) => {
  // Analyser le package.json pour vérifier les packages de rate limiting installés
  const packageJson = parsePackageJson(projectPath);
  const installedPackages = [];
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    const rateLimitingPackages = [
      'express-rate-limit',
      'rate-limiter-flexible', 
      'express-brute',
      'node-rate-limiter',
      'rate-limit-redis'
    ];
    
    for (const pkg of rateLimitingPackages) {
      if (dependencies && dependencies[pkg]) {
        installedPackages.push(pkg);
      }
    }
  }
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Chercher toutes les utilisations de rate limiting
  const rateLimitDetections = [];
  
  for (const pattern of rateLimitPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    if (results.length > 0) {
      rateLimitDetections.push({
        type: pattern.name,
        occurrences: results.map(r => ({ file: r.file, line: r.line, context: r.context }))
      });
    }
  }
  
  // Analyser les problèmes de configuration
  const configurationIssues = [];
  
  for (const pattern of rateLimitConfigPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      // Extraire la valeur pour certains patterns
      let value = null;
      if (pattern.threshold && result.context) {
        const match = result.context.match(pattern.pattern);
        if (match && match[1]) {
          value = parseInt(match[1], 10);
          
          // Ne signaler que si la valeur dépasse le seuil
          if (pattern.name === 'Limite de taux faible' && value <= pattern.threshold) {
            continue;
          }
          
          if (pattern.name === 'Fenêtre de temps de limite courte' && value >= pattern.threshold) {
            continue;
          }
        }
      }
      
      configurationIssues.push({
        file: result.file,
        line: result.line,
        name: pattern.name,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context,
        value: value
      });
    }
  }
  
  // Vérifier si les endpoints sensibles sont protégés
  const routeDefinitions = findFilesWithPattern(
    projectPath, 
    filePattern, 
    /app\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]/i
  );
  
  const unprotectedEndpoints = [];
  
  for (const route of routeDefinitions) {
    const context = route.context || '';
    const routeMatch = context.match(/app\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]/i);
    
    if (routeMatch && routeMatch[2]) {
      const path = routeMatch[2];
      const method = routeMatch[1].toUpperCase();
      
      // Vérifier si c'est un endpoint sensible
      const isSensitive = sensitivePaths.some(sensitive => 
        path === sensitive || path.includes(sensitive + '/'));
      
      if (isSensitive && method === 'POST') {
        // Vérifier si le rate limiting est appliqué à cet endpoint
        const routeIsProtected = findFilesWithPattern(
          projectPath,
          filePattern,
          new RegExp(`app\\.(?:use|${method.toLowerCase()})\\(\\s*['"\`]${path}['"\`]\\s*,\\s*(?:rateLimit|limiter)`, 'i')
        ).length > 0;
        
        if (!routeIsProtected) {
          unprotectedEndpoints.push({
            path,
            method,
            file: route.file,
            line: route.line
          });
        }
      }
    }
  }
  
  // Déterminer l'état global du rate limiting
  let rateLimit = '❌ Aucun système de rate-limiting détecté';
  
  if (rateLimitDetections.length > 0) {
    if (configurationIssues.length === 0 && unprotectedEndpoints.length === 0) {
      rateLimit = '✅ Rate-limiting correctement configuré';
    } else {
      rateLimit = '⚠️ Rate-limiting détecté mais mal configuré ou incomplet';
    }
  }
  
  // Calculer un score de sécurité (0-100)
  let securityScore = 0;
  
  if (rateLimitDetections.length > 0) {
    securityScore = 50; // Base score pour avoir un rate limiting
    
    // Ajouter des points pour chaque package installé
    securityScore += Math.min(20, installedPackages.length * 5);
    
    // Déduire des points pour les problèmes de configuration
    securityScore -= Math.min(40, configurationIssues.length * 10);
    
    // Déduire des points pour les endpoints non protégés
    securityScore -= Math.min(30, unprotectedEndpoints.length * 10);
  }
  
  // Limiter le score à 0-100
  securityScore = Math.max(0, Math.min(100, securityScore));
  
  return {
    status: rateLimit,
    installed: {
      packages: installedPackages,
      count: installedPackages.length
    },
    detected: {
      implementations: rateLimitDetections,
      count: rateLimitDetections.length
    },
    issues: {
      configurationProblems: configurationIssues,
      unprotectedEndpoints: unprotectedEndpoints,
      count: configurationIssues.length + unprotectedEndpoints.length
    },
    securityScore,
    recommendations: [
      'Installez express-rate-limit pour une protection de base',
      'Utilisez des limiteurs différents selon les endpoints (plus strict pour l\'authentification)',
      'Définissez une limite de taux global pour toutes les requêtes',
      'Utilisez un store distribué comme Redis pour les environnements à plusieurs instances',
      'Assurez-vous que tous les endpoints sensibles ont une limitation de taux stricte'
    ],
    recommendedImplementation: recommendedRateLimiter
  };
};