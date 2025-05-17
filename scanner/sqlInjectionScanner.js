const { findFilesWithPattern } = require('../utils/fileUtils');

// Motifs pour détecter les injections SQL potentielles
const sqlInjectionPatterns = [
  {
    type: 'Requête SQL brute',
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+.*\s+FROM\s+/i,
    severity: 'MEDIUM',
    solution: 'Utilisez des requêtes préparées avec des paramètres liés'
  },
  {
    type: 'Concaténation SQL',
    pattern: /(con|connection|db|database|sql)\.query\(\s*['"`].*?\$\{.*?\}/i,
    severity: 'HIGH',
    solution: 'Utilisez des requêtes préparées avec des paramètres liés plutôt que la concaténation de chaînes'
  },
  {
    type: 'Concaténation SQL',
    pattern: /(con|connection|db|database|sql)\.query\(\s*['"`].*?\s*\+\s*/i,
    severity: 'HIGH',
    solution: 'Utilisez des requêtes préparées avec des paramètres liés plutôt que la concaténation de chaînes'
  },
  {
    type: 'Raw queries sans validation',
    pattern: /\braw\s*\(\s*['"`].*?['"`]/i,
    severity: 'MEDIUM',
    solution: 'Assurez-vous de valider toutes les entrées avant d\'exécuter des requêtes SQL brutes'
  },
  {
    type: 'Sequelize Query Raw',
    pattern: /sequelize\.query\(\s*['"`]/i,
    severity: 'LOW',
    solution: 'Préférez l\'utilisation des méthodes du modèle Sequelize plutôt que des requêtes brutes'
  }
];

// Motifs pour détecter les injections NoSQL potentielles
const noSqlInjectionPatterns = [
  {
    type: 'MongoDB Find avec filtre non validé',
    pattern: /\.(find|findOne)\(\s*\{\s*(\$where|\.\.)\s*:/i,
    severity: 'HIGH',
    solution: 'N\'utilisez pas l\'opérateur $where ou d\'expressions JavaScript dans les requêtes MongoDB'
  },
  {
    type: 'MongoDB Find avec variable dynamique',
    pattern: /\.(find|findOne)\(\s*\{\s*[^:}]+\s*:\s*req\.(body|params|query)/i,
    severity: 'MEDIUM',
    solution: 'Validez toutes les entrées utilisateur avant de les utiliser dans des requêtes MongoDB'
  },
  {
    type: 'MongoDB Update avec positionnement dynamique',
    pattern: /\.(updateOne|updateMany)\(\s*\{\s*[^:}]+\s*:\s*req\.(body|params|query)/i,
    severity: 'MEDIUM',
    solution: 'Validez toutes les entrées utilisateur avant de les utiliser dans des opérations de mise à jour MongoDB'
  },
  {
    type: 'MongoDB Update avec opérateur $set dynamique',
    pattern: /\.(updateOne|updateMany)\([^{]*,\s*\{\s*\$set\s*:\s*req\.(body|params|query)/i,
    severity: 'HIGH',
    solution: 'Ne définissez pas directement l\'opérateur $set à partir des données utilisateur. Validez les champs individuellement'
  },
  {
    type: 'Mongoose unsafe queries',
    pattern: /Model\s*\.\s*(find|findOne|findById)\s*\(\s*req\.(body|params|query)/i,
    severity: 'MEDIUM',
    solution: 'Validez les entrées utilisateur avant de les utiliser dans des requêtes Mongoose'
  }
];

const recommendedPackages = [
  'express-validator',
  'joi',
  'yup',
  'validator',
  'sequelize',
  'mongoose',
  'mysql2',
  'pg',
  'sanitize-html'
];

exports.scanSqlInjections = (projectPath) => {
  const sqlVulnerabilities = [];
  const noSqlVulnerabilities = [];
  
  // Fichiers JavaScript et TypeScript
  const filePattern = '**/*.{js,ts,jsx,tsx}';
  
  // Vérifier les vulnérabilités SQL
  for (const pattern of sqlInjectionPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      sqlVulnerabilities.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  // Vérifier les vulnérabilités NoSQL
  for (const pattern of noSqlInjectionPatterns) {
    const results = findFilesWithPattern(projectPath, filePattern, pattern.pattern);
    
    for (const result of results) {
      noSqlVulnerabilities.push({
        file: result.file,
        line: result.line,
        type: pattern.type,
        severity: pattern.severity,
        solution: pattern.solution,
        context: result.context
      });
    }
  }
  
  return {
    sql: sqlVulnerabilities,
    noSql: noSqlVulnerabilities,
    recommendedPackages,
    total: sqlVulnerabilities.length + noSqlVulnerabilities.length
  };
}; 