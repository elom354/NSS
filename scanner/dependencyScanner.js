const { execSync } = require('child_process');
const { parsePackageJson } = require('../utils/fileUtils');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

/**
 * Analyse les dépendances avec npm audit
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Résultats de l'analyse
 */
const npmAuditAnalysis = (projectPath) => {
  try {
    const auditOutput = execSync('npm audit --json', { cwd: projectPath }).toString();
    const auditJson = JSON.parse(auditOutput);
    const vulnerabilities = auditJson.metadata.vulnerabilities;
    
    // Extraire les détails des vulnérabilités
    const detailedVulnerabilities = auditJson.advisories ? 
      Object.values(auditJson.advisories).map(a => ({
        name: a.module_name,
        severity: a.severity,
        title: a.title,
        vulnerable_versions: a.vulnerable_versions,
        recommendation: a.recommendation,
        url: a.url,
        cwe: a.cwe
      })) : [];
    
    return {
      metadata: vulnerabilities,
      vulnerabilities: detailedVulnerabilities,
      success: true
    };
  } catch (err) {
    return { 
      success: false, 
      error: 'npm audit failed or no vulnerabilities found.', 
      details: err.message 
    };
  }
};

/**
 * Analyse les dépendances obsolètes avec npm outdated
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Résultats de l'analyse
 */
const npmOutdatedAnalysis = (projectPath) => {
  try {
    const outdatedOutput = execSync('npm outdated --json', { cwd: projectPath }).toString();
    const outdatedJson = JSON.parse(outdatedOutput);
    
    // Formater les résultats
    const outdatedDeps = Object.keys(outdatedJson).map(packageName => ({
      name: packageName,
      current: outdatedJson[packageName].current,
      wanted: outdatedJson[packageName].wanted,
      latest: outdatedJson[packageName].latest,
      dependent: outdatedJson[packageName].dependent,
      riskLevel: calculateRiskLevel(outdatedJson[packageName].current, outdatedJson[packageName].latest)
    }));
    
    return {
      outdated: outdatedDeps,
      count: outdatedDeps.length,
      success: true
    };
  } catch (err) {
    return { 
      success: false, 
      error: 'npm outdated failed or no outdated dependencies found.', 
      details: err.message,
      outdated: []
    };
  }
};

/**
 * Calcule le niveau de risque en fonction de l'écart de version
 * @param {string} current - Version actuelle
 * @param {string} latest - Dernière version
 * @returns {string} - Niveau de risque
 */
const calculateRiskLevel = (current, latest) => {
  if (!current || !latest) return 'UNKNOWN';
  
  const currentParts = current.split('.').map(Number);
  const latestParts = latest.split('.').map(Number);
  
  // Vérifier les versions majeure, mineure, patch
  if (currentParts[0] < latestParts[0]) {
    const diff = latestParts[0] - currentParts[0];
    return diff >= 2 ? 'HIGH' : 'MEDIUM';
  } else if (currentParts[1] < latestParts[1]) {
    const diff = latestParts[1] - currentParts[1];
    return diff >= 5 ? 'MEDIUM' : 'LOW';
  } else if (currentParts[2] < latestParts[2]) {
    const diff = latestParts[2] - currentParts[2];
    return diff >= 10 ? 'LOW' : 'INFO';
  }
  
  return 'NONE';
};

/**
 * Vérifie les dépendances non utilisées
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Liste des dépendances non utilisées
 */
const checkUnusedDependencies = (projectPath) => {
  try {
    // Vérifier si depcheck est installé globalement
    try {
      execSync('npm list -g depcheck', { stdio: 'ignore' });
    } catch (e) {
      // Installer temporairement depcheck si nécessaire
      execSync('npm install -g depcheck', { stdio: 'ignore' });
    }
    
    const depcheckOutput = execSync(`depcheck ${projectPath} --json`, { stdio: 'pipe' }).toString();
    const depcheckResult = JSON.parse(depcheckOutput);
    
    return {
      unused: depcheckResult.dependencies || [],
      success: true
    };
  } catch (err) {
    return {
      success: false,
      error: 'Analyse des dépendances non utilisées a échoué',
      details: err.message,
      unused: []
    };
  }
};

/**
 * Analyse les licences des dépendances
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Informations sur les licences
 */
const analyzeLicenses = (projectPath) => {
  try {
    const licensesOutput = execSync('npm list --json', { cwd: projectPath }).toString();
    const licensesJson = JSON.parse(licensesOutput);
    
    // Extraire les informations de licence si disponibles
    const extractLicenses = (dependencies) => {
      if (!dependencies) return [];
      
      const licenses = [];
      for (const [name, info] of Object.entries(dependencies)) {
        if (info.licenses || info.license) {
          licenses.push({
            name,
            license: info.license || (Array.isArray(info.licenses) ? info.licenses.join(', ') : info.licenses)
          });
        }
        
        // Récursion pour les dépendances imbriquées
        if (info.dependencies) {
          licenses.push(...extractLicenses(info.dependencies));
        }
      }
      
      return licenses;
    };
    
    const licenses = extractLicenses(licensesJson.dependencies);
    
    return {
      licenses,
      count: licenses.length,
      success: true
    };
  } catch (err) {
    return {
      success: false,
      error: 'Analyse des licences a échoué',
      details: err.message,
      licenses: []
    };
  }
};

/**
 * Analyse des dépendances avec Snyk si disponible
 * @param {string} projectPath - Chemin du projet
 * @returns {Object} - Résultats de l'analyse Snyk
 */
const snykAnalysis = (projectPath) => {
  try {
    // Vérifier si Snyk est installé
    try {
      execSync('snyk --version', { stdio: 'ignore' });
    } catch (e) {
      return {
        success: false,
        error: 'Snyk n\'est pas installé ou n\'est pas accessible',
        vulnerabilities: []
      };
    }
    
    // Exécuter l'analyse Snyk
    const snykOutput = execSync('snyk test --json', { cwd: projectPath }).toString();
    const snykResult = JSON.parse(snykOutput);
    
    // Formater les résultats
    const vulnerabilities = snykResult.vulnerabilities.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      package: vuln.package,
      version: vuln.version,
      severity: vuln.severity,
      exploitMaturity: vuln.exploitMaturity,
      description: vuln.description,
      from: vuln.from,
      upgradePath: vuln.upgradePath
    }));
    
    return {
      success: true,
      vulnerabilities,
      total: vulnerabilities.length,
      packageManager: snykResult.packageManager,
      summary: {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
      }
    };
  } catch (err) {
    return {
      success: false,
      error: 'Analyse Snyk a échoué',
      details: err.message,
      vulnerabilities: []
    };
  }
};

/**
 * Vérification des bonnes pratiques pour les dépendances
 * @param {Object} packageJson - Contenu du package.json
 * @returns {Object} - Résultats de l'analyse
 */
const checkDependencyBestPractices = (packageJson) => {
  const issues = [];
  
  // Vérifier les versions épinglées
  if (packageJson.dependencies) {
    for (const [dep, version] of Object.entries(packageJson.dependencies)) {
      if (version.startsWith('^') || version.startsWith('~')) {
        issues.push({
          type: 'Version non épinglée',
          severity: 'LOW',
          package: dep,
          version,
          solution: `Épinglez la version exacte en supprimant les préfixes ^ ou ~ (ex: "${dep}": "${version.substring(1)}")`
        });
      }
    }
  }
  
  // Vérifier les scripts npm personnalisés
  if (packageJson.scripts) {
    for (const [scriptName, scriptCmd] of Object.entries(packageJson.scripts)) {
      if (scriptCmd.includes('&&') || scriptCmd.includes('||') || scriptCmd.includes(';')) {
        issues.push({
          type: 'Script npm complexe',
          severity: 'INFO',
          script: scriptName,
          command: scriptCmd,
          solution: 'Envisagez d\'utiliser un fichier de script séparé pour les commandes complexes'
        });
      }
    }
  }
  
  return {
    issues,
    count: issues.length
  };
};

exports.scanDependencies = async (projectPath) => {
  // Analyser le package.json
  const packageJson = parsePackageJson(projectPath);
  if (!packageJson) {
    return { error: 'package.json non trouvé ou invalide' };
  }
  
  // Exécuter toutes les analyses
  const npmAudit = npmAuditAnalysis(projectPath);
  const npmOutdated = npmOutdatedAnalysis(projectPath);
  const unusedDeps = checkUnusedDependencies(projectPath);
  const licenses = analyzeLicenses(projectPath);
  const snyk = snykAnalysis(projectPath);
  const bestPractices = checkDependencyBestPractices(packageJson);
  
  // Calculer un score de sécurité (0-100)
  let securityScore = 100;
  
  // Déduire des points pour les vulnérabilités
  if (npmAudit.success) {
    securityScore -= (npmAudit.metadata.critical * 20);
    securityScore -= (npmAudit.metadata.high * 10);
    securityScore -= (npmAudit.metadata.moderate * 5);
    securityScore -= (npmAudit.metadata.low * 2);
  }
  
  // Déduire des points pour les dépendances obsolètes
  if (npmOutdated.success) {
    const highRiskOutdated = npmOutdated.outdated.filter(d => d.riskLevel === 'HIGH').length;
    const mediumRiskOutdated = npmOutdated.outdated.filter(d => d.riskLevel === 'MEDIUM').length;
    
    securityScore -= (highRiskOutdated * 5);
    securityScore -= (mediumRiskOutdated * 2);
  }
  
  // Limiter le score à 0-100
  securityScore = Math.max(0, Math.min(100, securityScore));
  
  return {
    audit: npmAudit.success ? {
      vulnerabilities: npmAudit.metadata,
      details: npmAudit.vulnerabilities
    } : { error: npmAudit.error },
    
    outdated: npmOutdated.success ? {
      count: npmOutdated.count,
      packages: npmOutdated.outdated
    } : { error: npmOutdated.error },
    
    unused: unusedDeps.success ? {
      count: unusedDeps.unused.length,
      packages: unusedDeps.unused
    } : { error: unusedDeps.error },
    
    licenses: licenses.success ? {
      count: licenses.count,
      list: licenses.licenses
    } : { error: licenses.error },
    
    snyk: snyk.success ? {
      summary: snyk.summary,
      vulnerabilities: snyk.vulnerabilities
    } : { error: snyk.error },
    
    bestPractices: bestPractices,
    
    securityScore: securityScore,
    
    recommendations: [
      'Mettez à jour régulièrement vos dépendances',
      'Utilisez npm audit ou snyk régulièrement',
      'Épinglez les versions exactes des dépendances',
      'Utilisez un lockfile (package-lock.json)',
      'Vérifiez les licences des dépendances',
      'Supprimez les dépendances non utilisées'
    ]
  };
};