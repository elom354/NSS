// index.js
const path = require('path');
const { scanDependencies } = require('./scanner/dependencyScanner');
const { scanSecrets } = require('./scanner/secretScanner');
const { scanMiddlewares } = require('./scanner/middlewareScanner');
const { scanCORS } = require('./scanner/corsScanner');
const { scanRateLimit } = require('./scanner/rateLimitScanner');
const { scanSqlInjections } = require('./scanner/sqlInjectionScanner');
const { scanAuthentication } = require('./scanner/authScanner');
const { scanInputValidation } = require('./scanner/inputValidationScanner');
const { scanCSRF } = require('./scanner/csrfScanner');
const { scanCookies } = require('./scanner/cookieScanner');
const { generateReport } = require('./scanner/reportGenerator');

// Affiche une bannière ASCII au démarrage
const showBanner = () => {
  console.log(`
  ███╗   ██╗ ██████╗ ██████╗ ███████╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
  ████╗  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
  ██╔██╗ ██║██║   ██║██║  ██║█████╗  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
  ██║╚██╗██║██║   ██║██║  ██║██╔══╝  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
  ██║ ╚████║╚██████╔╝██████╔╝███████╗███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
  ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                         ███████╗ ██████╗ █████╗ ███╗   ██╗                           
                         ██╔════╝██╔════╝██╔══██╗████╗  ██║                           
                         ███████╗██║     ███████║██╔██╗ ██║                           
                         ╚════██║██║     ██╔══██║██║╚██╗██║                           
                         ███████║╚██████╗██║  ██║██║ ╚████║                           
                         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  v1.0.0                  
  `);
};

// Fonction principale d'analyse
(async () => {
  try {
    showBanner();

    // Vérifier les arguments de la ligne de commande
    const targetDir = process.argv[2];
    if (!targetDir) {
      console.error('❌ Veuillez spécifier le chemin du projet à scanner.');
      console.log('\nUtilisation: node index.js <chemin-du-projet>');
      process.exit(1);
    }

    const absolutePath = path.resolve(targetDir);
    console.log(`🔍 Scan du projet : ${absolutePath}\n`);

    // Démarrer le chronomètre pour mesurer le temps d'analyse
    const startTime = process.hrtime();

    console.log('⏳ Analyse des dépendances...');
    const dependencies = await scanDependencies(absolutePath);
    
    console.log('⏳ Recherche de secrets exposés...');
    const secrets = await scanSecrets(absolutePath);
    
    console.log('⏳ Analyse des middlewares de sécurité...');
    const middlewares = await scanMiddlewares(absolutePath);
    
    console.log('⏳ Vérification de la configuration CORS...');
    const cors = await scanCORS(absolutePath);
    
    console.log('⏳ Analyse des protections par rate limiting...');
    const rateLimit = await scanRateLimit(absolutePath);
    
    console.log('⏳ Détection des vulnérabilités d\'injection SQL/NoSQL...');
    const sqlInjection = await scanSqlInjections(absolutePath);
    
    console.log('⏳ Analyse des mécanismes d\'authentification...');
    const auth = await scanAuthentication(absolutePath);
    
    console.log('⏳ Vérification de la validation des entrées...');
    const inputValidation = await scanInputValidation(absolutePath);
    
    console.log('⏳ Analyse des protections CSRF...');
    const csrf = await scanCSRF(absolutePath);
    
    console.log('⏳ Vérification de la gestion des cookies...');
    const cookies = await scanCookies(absolutePath);

    // Temps d'analyse total
    const hrend = process.hrtime(startTime);
    const executionTimeInSeconds = (hrend[0] + (hrend[1] / 1e9)).toFixed(2);
    
    console.log(`\n✅ Analyse terminée en ${executionTimeInSeconds} secondes.`);
    
    // Résumé des résultats
    const vulnCount = 
      (dependencies.audit ? Object.values(dependencies.audit.vulnerabilities || {}).reduce((a, b) => a + b, 0) : 0) +
      (secrets.secrets ? secrets.secrets.length : 0) +
      (middlewares.missing ? middlewares.missing.count : 0) +
      (sqlInjection ? sqlInjection.total : 0) + 
      (auth ? auth.total : 0) + 
      (inputValidation ? inputValidation.total : 0) + 
      (csrf ? csrf.total : 0) + 
      (cookies ? cookies.total : 0);
    
    console.log(`🔍 Résumé: ${vulnCount} problèmes de sécurité potentiels détectés.`);
    
    // Générer le rapport final
    console.log('📊 Génération du rapport de sécurité...');

    const results = {
      dependencies,
      secrets,
      middlewares,
      cors,
      rateLimit,
      sqlInjection,
      auth,
      inputValidation,
      csrf,
      cookies,
      stats: {
        executionTime: executionTimeInSeconds,
        totalIssues: vulnCount
      }
    };

    const reportPath = await generateReport(results);
    console.log(`\n🎉 Rapport de sécurité généré avec succès : ${reportPath}`);
  } catch (error) {
    console.error('❌ Une erreur est survenue lors de l\'analyse:', error);
    process.exit(1);
  }
})();
