const { findFilesWithPattern, parsePackageJson } = require('../utils/fileUtils');

// Motifs pour la détection de CORS
const corsPatterns = [
  {
    name: 'CORS permissif avec wildcard',
    pattern: /cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/i,
    severity: 'HIGH',
    solution: 'Limitez les origines CORS à des domaines spécifiques en utilisant un tableau ou une fonction'
  },
  {
    name: 'CORS avec credentials',
    pattern: /cors\(\s*\{\s*(?:[^}]*\s*,\s*)?credentials\s*:\s*true/i,
    severity: 'MEDIUM',
    solution: 'Vérifiez que credentials: true est utilisé uniquement avec des origines spécifiques, jamais avec *'
  },
  {
    name: 'CORS avec méthodes permissives',
    pattern: /cors\(\s*\{\s*(?:[^}]*\s*,\s*)?methods\s*:\s*['"`](GET,\s*POST,\s*PUT,\s*DELETE,\s*PATCH|[^'"]*\*[^'"]*)['"`]/i,
    severity: 'MEDIUM',
    solution: 'Limitez les méthodes HTTP à celles strictement nécessaires pour votre API'
  },
  {
    name: 'CORS avec allowedHeaders permissifs',
    pattern: /cors\(\s*\{\s*(?:[^}]*\s*,\s*)?allowedHeaders\s*:\s*['"`]\*['"`]/i,
    severity: 'MEDIUM',
    solution: 'Spécifiez explicitement les en-têtes autorisés au lieu d\'utiliser *'
  }
];

// Configuration CORS recommandée
const corsRecommendedConfig = `
app.use(cors({
  origin: ['https://example.com', 'https://app.example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 3600
}));`;

exports.scanCORS = (projectPath) => {
  // Analyser le package.json pour vérifier si cors est installé
  const packageJson = parsePackageJson(projectPath);
  let corsInstalled = false;
  
  if (packageJson) {
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    corsInstalled = dependencies && dependencies['cors'];
  }
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Chercher toutes les utilisations de CORS
  const corsUsage = findFilesWithPattern(projectPath, filePattern, /cors\(/i);
  const corsDetected = corsUsage.length > 0;
  
  // Chercher les utilisations de headers CORS manuels
  const manualCorsHeaders = findFilesWithPattern(
    projectPath, 
    filePattern, 
    /res\.header\(['"`](Access-Control-Allow-|Origin)/i
  );
  
  // Chercher les problèmes de configuration CORS
  const corsIssues = [];
  
  for (const pattern of corsPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      corsIssues.push({
        file: result.file,
        line: result.line,
        name: pattern.name,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Déterminer l'état global de la configuration CORS
  let corsStatus = '❌ Aucun CORS détecté';
  
  if (corsDetected) {
    const wildcardOrigin = corsIssues.some(issue => issue.name === 'CORS permissif avec wildcard');
    
    if (wildcardOrigin) {
      corsStatus = '⚠️ CORS permissif (*) détecté';
    } else {
      corsStatus = '✅ CORS restreint';
    }
  } else if (manualCorsHeaders.length > 0) {
    corsStatus = '⚠️ Configuration CORS manuelle détectée';
  }
  
  // Analyser les configurations CORS spécifiques
  let corsConfigurations = [];
  
  if (corsUsage.length > 0) {
    corsConfigurations = corsUsage.map(result => {
      const context = result.context || '';
      
      // Essayer d'extraire la configuration d'origine
      let origin = 'Non détectée';
      const originMatch = context.match(/origin\s*:\s*([^,}]+)/i);
      if (originMatch) {
        origin = originMatch[1].trim();
      }
      
      // Essayer d'extraire la configuration de credentials
      let credentials = 'Non détectée';
      const credentialsMatch = context.match(/credentials\s*:\s*([^,}]+)/i);
      if (credentialsMatch) {
        credentials = credentialsMatch[1].trim();
      }
      
      return {
        file: result.file,
        line: result.line,
        origin,
        credentials,
        context
      };
    });
  }
  
  // Analyser l'utilisation de middleware helmet (peut configurer CORS)
  const helmetUsage = findFilesWithPattern(projectPath, filePattern, /helmet\(/i);
  const helmetDetected = helmetUsage.length > 0;
  
  // Calculer un score de sécurité CORS (0-100)
  let corsSecurityScore = 0;
  
  if (corsDetected || manualCorsHeaders.length > 0) {
    corsSecurityScore = 50; // Base score for having CORS
    
    // Vérifier si CORS n'est pas permissif
    if (!corsIssues.some(issue => issue.name === 'CORS permissif avec wildcard')) {
      corsSecurityScore += 25;
    }
    
    // Vérifier s'il n'y a pas de problème de sévérité élevée
    if (!corsIssues.some(issue => issue.severity === 'HIGH')) {
      corsSecurityScore += 15;
    }
    
    // Vérifier s'il y a peu ou pas de problèmes de sévérité moyenne
    const mediumIssues = corsIssues.filter(issue => issue.severity === 'MEDIUM').length;
    if (mediumIssues === 0) {
      corsSecurityScore += 10;
    } else if (mediumIssues <= 1) {
      corsSecurityScore += 5;
    }
  }
  
  return {
    installed: corsInstalled,
    detected: corsDetected || manualCorsHeaders.length > 0,
    status: corsStatus,
    issues: corsIssues,
    configurations: corsConfigurations,
    manualHeaders: manualCorsHeaders.length > 0,
    helmetUsed: helmetDetected,
    securityScore: corsSecurityScore,
    recommendations: [
      'Limitez les origines CORS à des domaines spécifiques',
      'Ne configurez jamais CORS avec * si credentials: true est utilisé',
      'Spécifiez explicitement les méthodes HTTP autorisées',
      'Définissez un maxAge approprié pour les requêtes preflight'
    ],
    recommendedConfig: corsRecommendedConfig
  };
};