const { findFilesWithPattern } = require('../utils/fileUtils');

// Définition des motifs de recherche améliorés
const secretPatterns = [
  {
    type: 'API Key',
    pattern: /(['"])?(api[_-]?key|auth[_-]?key|access[_-]?key)['"]\s*[=:]\s*['"]([a-zA-Z0-9_\-]{10,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'Secret Key',
    pattern: /(['"])?(secret[_-]?key|client[_-]?secret)['"]\s*[=:]\s*['"]([a-zA-Z0-9_\-]{10,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'Password',
    pattern: /(['"])?(password|passwd|pwd)['"]\s*[=:]\s*['"]([^'"]{4,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'Token',
    pattern: /(['"])?(token|jwt|auth[_-]?token)['"]\s*[=:]\s*['"]([a-zA-Z0-9_\-.+=]{10,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'AWS Access Key',
    pattern: /(['"])?aws[_-]?access[_-]?key[_-]?id['"]\s*[=:]\s*['"]([A-Z0-9]{20})['"]/i,
    severity: 'CRITICAL'
  },
  {
    type: 'AWS Secret Key',
    pattern: /(['"])?aws[_-]?secret[_-]?access[_-]?key['"]\s*[=:]\s*['"]([a-zA-Z0-9/+]{40})['"]/i,
    severity: 'CRITICAL'
  },
  {
    type: 'Google API Key',
    pattern: /(['"])?AIza[0-9A-Za-z\-_]{35}['"]/i,
    severity: 'CRITICAL'
  },
  {
    type: 'Private Key',
    pattern: /-----BEGIN\s+PRIVATE\s+KEY( BLOCK)?-----/i,
    severity: 'CRITICAL'
  },
  {
    type: 'Firebase Key',
    pattern: /(['"])?firebase[_-]?api[_-]?key['"]\s*[=:]\s*['"]([a-zA-Z0-9_\-]{10,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'GitHub Token',
    pattern: /(['"])?github[_-]?token['"]\s*[=:]\s*['"]([a-zA-Z0-9_\-]{10,})['"]/i,
    severity: 'HIGH'
  },
  {
    type: 'MongoDB Connection String',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+\/[a-zA-Z0-9-_]+/i,
    severity: 'CRITICAL'
  },
  {
    type: 'Environment Variable',
    pattern: /process\.env\.([A-Za-z0-9_]+)/i,
    severity: 'INFO',
    isEnvVar: true
  }
];

// Fichiers et répertoires à exclure
const excludedDirs = ['node_modules', '.git', 'dist', 'build', 'public'];
const fileExtensions = ['js', 'ts', 'jsx', 'tsx', 'json', 'env', 'config', 'yml', 'yaml'];

exports.scanSecrets = (projectPath) => {
  const matches = [];
  const envVars = new Set();
  
  // Crée un motif pour les fichiers à scanner
  const filePattern = `**/*.{${fileExtensions.join(',')}}`;
  
  // Scanner pour chaque type de secret
  for (const secretDef of secretPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, secretDef.pattern);
    
    for (const result of results) {
      // Ignorer les fichiers dans les dossiers exclus
      if (excludedDirs.some(dir => result.file.includes(`/${dir}/`))) {
        continue;
      }
      
      // Si c'est une variable d'environnement, l'ajouter à la liste
      if (secretDef.isEnvVar) {
        const match = result.context && result.context.match(secretDef.pattern);
        if (match && match[1]) {
          envVars.add(match[1]);
        }
        continue;
      }
      
      matches.push({
        file: result.file,
        line: result.line,
        type: secretDef.type,
        severity: secretDef.severity,
        context: result.context
      });
    }
  }
  
  // Vérifier les fichiers .env pour s'assurer que les variables d'environnement sont définies
  const envResults = findFilesWithPattern(projectPath, '**/.env*', /.+/);
  const envFileVars = new Set();
  
  for (const result of envResults) {
    // Extraire les noms de variables des fichiers .env
    const content = result.context || '';
    const envVarMatches = content.match(/^([A-Za-z0-9_]+)=/gm);
    if (envVarMatches) {
      envVarMatches.forEach(match => {
        const varName = match.replace('=', '');
        envFileVars.add(varName);
      });
    }
  }
  
  // Ajouter un rapport sur les variables d'environnement
  return {
    secrets: matches,
    environmentVariables: {
      used: Array.from(envVars),
      defined: Array.from(envFileVars),
      missing: Array.from(envVars).filter(v => !envFileVars.has(v))
    }
  };
};