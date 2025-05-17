const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const { createCanvas } = require('canvas');

const solutionHints = {
  helmet: `Installez \`helmet\` pour ajouter des headers de sécurité HTTP. Exemple : app.use(require("helmet")());`,
  'xss-clean': `Installez \`xss-clean\` pour prévenir les attaques XSS. Exemple : app.use(require("xss-clean")());`,
  'express-rate-limit': `Ajoutez un middleware de rate-limit. Exemple : app.use(require("express-rate-limit")({...}));`,
  cors: `Installez et configurez \`cors\` avec une origine spécifique. Exemple : app.use(cors({ origin: "https://votresite.com" }));`,
  secrets: `Ne stockez jamais vos secrets (API_KEY, TOKEN, etc.) dans le code source. Utilisez des variables d'environnement.`,
  csurf: `Installez \`csurf\` pour la protection CSRF. Exemple : app.use(require("csurf")({ cookie: true }));`,
  'express-validator': `Validez les entrées utilisateur avec \`express-validator\`. Exemple : app.use(body().trim().escape());`,
  sanitize: `Nettoyez les entrées utilisateur avec \`sanitize-html\`. Exemple : sanitizeHtml(userInput, {...});`,
  passwords: `Hachez les mots de passe avec \`bcrypt\` ou \`argon2\`. Exemple : bcrypt.hash(password, 10);`,
  sql: `Utilisez des requêtes préparées avec paramètres. Exemple : db.query("SELECT * FROM users WHERE id = ?", [id]);`,
  nosql: `Validez les entrées avant de les utiliser dans les requêtes MongoDB. Évitez les opérateurs comme $where.`
};

// Définitions de couleurs pour le rapport
const colors = {
  critical: '#FF0000',
  high: '#FF3333',
  medium: '#FF9933',
  low: '#FFCC00',
  info: '#3366FF',
  success: '#00CC66',
  title: '#333333',
  subtitle: '#555555',
  text: '#000000',
  highlight: '#0066CC',
  background: '#F8F8F8',
  graphBg: '#FFFFFF'
};

/**
 * Génère un graphique avec la bibliothèque canvas et le convertit en Buffer
 * @param {Object} data - Données pour le graphique
 * @param {string} type - Type de graphique (pie, bar, etc.)
 * @param {string} title - Titre du graphique
 * @param {number} width - Largeur du graphique
 * @param {number} height - Hauteur du graphique
 * @returns {Buffer} - Buffer contenant l'image du graphique
 */
const generateChartImage = (data, type, title, width = 500, height = 300) => {
  const canvas = createCanvas(width, height);
  const ctx = canvas.getContext('2d');
  
  // Fond blanc
  ctx.fillStyle = colors.graphBg;
  ctx.fillRect(0, 0, width, height);
  
  // Ajouter un cadre
  ctx.strokeStyle = '#CCCCCC';
  ctx.lineWidth = 2;
  ctx.strokeRect(3, 3, width - 6, height - 6);
  
  // Titre
  ctx.fillStyle = colors.title;
  ctx.font = 'bold 16px Arial';
  ctx.textAlign = 'center';
  ctx.fillText(title, width / 2, 25);
  
  if (type === 'pie') {
    // Graphique en camembert
    const total = Object.values(data).reduce((sum, val) => sum + val, 0);
    if (total === 0) return canvas.toBuffer();
    
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 60;
    
    let startAngle = 0;
    let i = 0;
    
    // Couleurs pour le camembert
    const pieColors = [
      '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', 
      '#FF9F40', '#8AC054', '#F49AC2', '#82B1FF', '#FFCC80'
    ];
    
    // Légende
    ctx.font = '14px Arial';
    ctx.textAlign = 'left';
    let legendY = height - 20 - (Object.keys(data).length * 25);
    
    for (const [label, value] of Object.entries(data)) {
      if (value === 0) continue;
      
      const sliceAngle = 2 * Math.PI * value / total;
      
      // Dessiner la part
      ctx.beginPath();
      ctx.fillStyle = pieColors[i % pieColors.length];
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
      ctx.closePath();
      ctx.fill();
      
      // Légende
      ctx.fillStyle = pieColors[i % pieColors.length];
      ctx.fillRect(width - 180, legendY, 15, 15);
      ctx.fillStyle = colors.text;
      ctx.fillText(`${label}: ${value}`, width - 160, legendY + 12);
      
      startAngle += sliceAngle;
      i++;
      legendY += 25;
    }
  } else if (type === 'bar') {
    // Graphique à barres
    const barWidth = (width - 120) / Object.keys(data).length;
    const maxValue = Math.max(...Object.values(data));
    const barColors = [
      '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', 
      '#FF9F40', '#8AC054', '#F49AC2', '#82B1FF', '#FFCC80'
    ];
    
    let x = 60;
    let i = 0;
    
    // Axe Y
    ctx.strokeStyle = colors.text;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(50, 50);
    ctx.lineTo(50, height - 50);
    ctx.stroke();
    
    // Axe X
    ctx.beginPath();
    ctx.moveTo(50, height - 50);
    ctx.lineTo(width - 50, height - 50);
    ctx.stroke();
    
    for (const [label, value] of Object.entries(data)) {
      const barHeight = (value / maxValue) * (height - 120);
      
      // Dessiner la barre
      ctx.fillStyle = barColors[i % barColors.length];
      ctx.fillRect(x, height - 50 - barHeight, barWidth - 15, barHeight);
      
      // Étiquette de valeur
      ctx.fillStyle = colors.text;
      ctx.font = 'bold 14px Arial';
      ctx.textAlign = 'center';
      if (value > 0) {
        ctx.fillText(value.toString(), x + (barWidth - 15) / 2, height - 55 - barHeight);
      }
      
      // Étiquette
      ctx.fillStyle = colors.text;
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      
      // Rotation pour les étiquettes longues
      ctx.save();
      ctx.translate(x + (barWidth - 15) / 2, height - 35);
      ctx.rotate(-Math.PI / 6);
      ctx.fillText(label, 0, 0);
      ctx.restore();
      
      x += barWidth;
      i++;
    }
  }
  
  return canvas.toBuffer();
};

/**
 * Calcule un score de sécurité global (0-100)
 * @param {Object} results - Résultats de l'analyse
 * @returns {number} - Score de sécurité global
 */
const calculateSecurityScore = (results) => {
  let score = 100;
  
  // Déduire des points pour les vulnérabilités des dépendances
  if (results.dependencies && results.dependencies.audit) {
    const vuln = results.dependencies.audit.vulnerabilities;
    if (vuln) {
      score -= (vuln.critical || 0) * 15;
      score -= (vuln.high || 0) * 10;
      score -= (vuln.moderate || 0) * 5;
      score -= (vuln.low || 0) * 2;
    }
  }
  
  // Déduire des points pour les secrets détectés
  if (results.secrets && results.secrets.secrets) {
    const criticalSecrets = results.secrets.secrets.filter(s => s.severity === 'CRITICAL').length;
    const highSecrets = results.secrets.secrets.filter(s => s.severity === 'HIGH').length;
    
    score -= criticalSecrets * 10;
    score -= highSecrets * 5;
  }
  
  // Déduire des points pour les problèmes d'authentification
  if (results.auth && results.auth.total) {
    score -= Math.min(20, results.auth.total * 2);
  }
  
  // Déduire des points pour les problèmes de validation d'entrée
  if (results.inputValidation && results.inputValidation.total) {
    score -= Math.min(15, results.inputValidation.total * 1.5);
  }
  
  // Déduire des points pour les injections SQL/NoSQL
  if (results.sqlInjection && results.sqlInjection.total) {
    score -= Math.min(20, results.sqlInjection.total * 3);
  }
  
  // Déduire des points pour les problèmes CSRF
  if (results.csrf && results.csrf.total) {
    score -= Math.min(15, results.csrf.total * 2);
  }
  
  // Déduire des points pour les problèmes de CORS
  if (results.cors && results.cors.issues) {
    const highCorsIssues = results.cors.issues.filter(i => i.severity === 'HIGH').length;
    score -= highCorsIssues * 5;
  }
  
  // Déduire des points pour les problèmes de rate limiting
  if (results.rateLimit && results.rateLimit.issues) {
    score -= Math.min(10, results.rateLimit.issues.count);
  }
  
  // Déduire des points pour les middlewares manquants
  if (results.middlewares && results.middlewares.missing) {
    score -= Math.min(20, results.middlewares.missing.count * 4);
  }
  
  // Limiter le score entre 0 et 100
  return Math.max(0, Math.min(100, Math.round(score)));
};

/**
 * Génère un score de sécurité coloré en fonction du niveau
 * @param {number} score - Score de sécurité
 * @returns {Object} - Objet avec la couleur et le texte
 */
const getScoreInfo = (score) => {
  if (score >= 90) {
    return {
      color: colors.success,
      text: 'Excellent'
    };
  } else if (score >= 70) {
    return {
      color: colors.info,
      text: 'Bon'
    };
  } else if (score >= 50) {
    return {
      color: colors.medium,
      text: 'Moyen'
    };
  } else if (score >= 30) {
    return {
      color: colors.high,
      text: 'Mauvais'
    };
  } else {
    return {
      color: colors.critical,
      text: 'Critique'
    };
  }
};

/**
 * Fonction pour éviter les problèmes de coupure de texte dans PDFKit
 * @param {Object} doc - Document PDF
 * @param {string} text - Texte à écrire
 * @param {number} x - Position X
 * @param {number} y - Position Y
 * @param {Object} options - Options de texte
 */
const safelyAddText = (doc, text, x, y, options = {}) => {
  if (typeof text !== 'string') {
    text = String(text || '');
  }
  doc.text(text, x, y, options);
};

/**
 * Génère un rapport PDF sécurité pour le projet Node.js analysé
 * @param {Object} results - Résultats de l'analyse de sécurité
 */
exports.generateReport = async (results) => {
  // Créer le répertoire des rapports s'il n'existe pas
  const reportDir = path.join(__dirname, '../reports');
  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir);
  
  const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = path.join(reportDir, `security-scan-${dateStr}.pdf`);
  
  // Calculer le score de sécurité global
  const securityScore = calculateSecurityScore(results);
  const scoreInfo = getScoreInfo(securityScore);
  
  // Créer le document PDF
  const doc = new PDFDocument({
    margins: { top: 50, bottom: 50, left: 50, right: 50 },
    size: 'A4',
    info: {
      Title: 'Rapport de Sécurité NodeSecureScanner',
      Author: 'NodeSecureScanner',
      Subject: 'Analyse de sécurité Node.js',
      Keywords: 'sécurité, node.js, vulnérabilités, scan'
    }
  });
  
  doc.pipe(fs.createWriteStream(filename));

  // Fonctions d'aide pour la mise en page
  const addHeader = (text, options = {}) => {
    doc.font('Helvetica-Bold')
       .fontSize(18)
       .fillColor(options.color || colors.title);

    // Boîte pour le titre de la section
    const titleBoxHeight = 30;
    doc.rect(50, doc.y, doc.page.width - 100, titleBoxHeight)
       .fillColor(colors.background)
       .fill();

    doc.fillColor(options.color || colors.title)
       .text(text, 70, doc.y - titleBoxHeight + 8, { 
         underline: options.underline === true,
         width: doc.page.width - 140
       });

    doc.moveDown(1);
  };
  
  const addSubHeader = (text) => {
    doc.fontSize(14)
       .fillColor(colors.subtitle)
       .font('Helvetica-Bold')
       .text(text)
       .moveDown(0.5);
  };
  
  const addParagraph = (text) => {
    doc.fontSize(12)
       .fillColor(colors.text)
       .font('Helvetica')
       .text(text)
       .moveDown(0.5);
  };
  
  const addIssue = (issue, showSolution = true) => {
    doc.fontSize(12)
       .fillColor(colors.text)
       .font('Helvetica-Bold')
       .text(`• ${issue.type || issue.name}`, { continued: true })
       .font('Helvetica')
       .text(` (${issue.severity || 'INFO'})`, { underline: false });
    
    if (issue.file) {
      doc.fontSize(10)
         .fillColor(colors.info)
         .text(`  File: ${issue.file}${issue.line ? `, Line: ${issue.line}` : ''}`);
    }
    
    if (issue.context) {
      doc.fontSize(10)
         .fillColor(colors.text)
         .text(`  ${issue.context.trim().substring(0, 80)}${issue.context.length > 80 ? '...' : ''}`);
    }
    
    if (showSolution && issue.solution) {
      doc.fontSize(10)
         .fillColor(colors.highlight)
         .text(`  📝 ${issue.solution}`);
    }
    
    doc.moveDown(0.5);
  };
  
  const addRecommendation = (text) => {
    doc.fontSize(12)
       .fillColor(colors.highlight)
       .text(`✅ ${text}`)
       .moveDown(0.5);
  };
  
  // Page de garde
  doc.font('Helvetica-Bold')
     .fontSize(24)
     .fillColor(colors.title)
     .text('Rapport d\'Analyse de Sécurité', { align: 'center' })
     .moveDown(0.5);
  
  doc.fontSize(16)
     .fillColor(colors.subtitle)
     .text('NodeSecureScanner', { align: 'center' })
     .moveDown(2);
  
  // Date du rapport
  doc.fontSize(12)
     .fillColor(colors.text)
     .text(`Date du rapport: ${new Date().toLocaleString()}`, { align: 'center' })
     .moveDown(3);
  
  // Score global
  doc.fontSize(16)
     .fillColor(colors.title)
     .text('Score Global de Sécurité:', { align: 'center' })
     .moveDown(0.5);
  
  // Circle score avec couleur
  const scoreRadius = 50;
  const scoreX = doc.page.width / 2;
  const scoreY = doc.y + scoreRadius + 20;
  
  // Cercle de fond
  doc.circle(scoreX, scoreY, scoreRadius)
     .fillOpacity(0.3)
     .fillAndStroke(scoreInfo.color, scoreInfo.color);
  
  // Cercle principal
  doc.circle(scoreX, scoreY, scoreRadius - 5)
     .fillOpacity(1)
     .fillAndStroke('white', scoreInfo.color);
  
  // Score text
  doc.fontSize(24)
     .fillColor(scoreInfo.color)
     .text(securityScore, scoreX - 20, scoreY - 15, { align: 'center', width: 40 });
  
  // Évaluation
  doc.fontSize(12)
     .fillColor(scoreInfo.color)
     .text(scoreInfo.text, scoreX - 40, scoreY + 15, { align: 'center', width: 80 });
  
  doc.moveDown(4);
  
  // Légende
  doc.fontSize(12)
     .fillColor(colors.title)
     .font('Helvetica-Bold')
     .text('Niveaux de gravité:', 50, doc.y + 10)
     .moveDown(0.5);

  const severityLevels = [
    { name: 'CRITIQUE', color: colors.critical },
    { name: 'ÉLEVÉ', color: colors.high },
    { name: 'MOYEN', color: colors.medium },
    { name: 'FAIBLE', color: colors.low },
    { name: 'INFO', color: colors.info }
  ];

  for (const level of severityLevels) {
    doc.rect(50, doc.y, 20, 20)
       .fill(level.color);
    
    doc.fontSize(11)
       .fillColor(colors.text)
       .font('Helvetica-Bold')
       .text(level.name, 80, doc.y - 16)
       .moveDown(0.8);
  }
  
  // Nouvelle page - Sommaire et résumé
  doc.addPage();
  addHeader('Résumé Exécutif', { underline: true });
  
  // Créer un résumé des problèmes trouvés
  const issues = {
    dependencies: results.dependencies && results.dependencies.audit && results.dependencies.audit.vulnerabilities
      ? Object.values(results.dependencies.audit.vulnerabilities).reduce((a, b) => a + b, 0)
      : 0,
    secrets: results.secrets && results.secrets.secrets ? results.secrets.secrets.length : 0,
    middlewares: results.middlewares && results.middlewares.missing ? results.middlewares.missing.count : 0,
    auth: results.auth ? results.auth.total : 0,
    sqlInjection: results.sqlInjection ? results.sqlInjection.total : 0,
    inputValidation: results.inputValidation ? results.inputValidation.total : 0,
    csrf: results.csrf ? results.csrf.total : 0,
    cookies: results.cookies ? results.cookies.total : 0
  };
  
  // Summary text
  const summary = `Cette analyse a identifié un total de ${Object.values(issues).reduce((a, b) => a + b, 0)} problèmes de sécurité potentiels,
dont ${issues.dependencies} vulnérabilités dans les dépendances, ${issues.secrets} secrets exposés,
${issues.middlewares} middlewares de sécurité manquants, ${issues.auth} problèmes d'authentification,
${issues.sqlInjection} risques d'injections SQL/NoSQL, ${issues.inputValidation} problèmes de validation d'entrée,
et ${issues.csrf} vulnérabilités CSRF.

Le score global de sécurité de votre application est de ${securityScore}/100, ce qui correspond à une évaluation "${scoreInfo.text}".

Ce rapport détaille chaque problème identifié et fournit des recommandations concrètes pour améliorer
la sécurité de votre application Node.js.`;
  
  addParagraph(summary);
  
  // Add chart for issues summary
  try {
    const chartImage = generateChartImage({
      'Dépendances': issues.dependencies,
      'Secrets': issues.secrets,
      'Middlewares': issues.middlewares,
      'Auth': issues.auth,
      'SQL/NoSQL': issues.sqlInjection,
      'Validation': issues.inputValidation,
      'CSRF': issues.csrf,
      'Cookies': issues.cookies
    }, 'bar', 'Répartition des problèmes par catégorie', 500, 250);
    
    doc.image(chartImage, {
      fit: [500, 250],
      align: 'center'
    });
  } catch (err) {
    console.error('Error generating chart:', err);
  }
  
  doc.moveDown(1);
  
  addSubHeader('Actions Prioritaires');
  
  // Top priority recommendations
  const priorityRecommendations = [];
  
  if (issues.dependencies > 0) {
    priorityRecommendations.push('Mettez à jour les dépendances vulnérables identifiées dans ce rapport');
  }
  
  if (issues.secrets > 0) {
    priorityRecommendations.push('Déplacez immédiatement les informations sensibles détectées vers des variables d\'environnement');
  }
  
  if (issues.auth > 5) {
    priorityRecommendations.push('Améliorez les mécanismes d\'authentification et d\'autorisation');
  }
  
  if (issues.sqlInjection > 0) {
    priorityRecommendations.push('Corrigez les vulnérabilités d\'injection SQL/NoSQL en priorité');
  }
  
  if (issues.middlewares > 3) {
    priorityRecommendations.push('Ajoutez les middlewares de sécurité essentiels manquants');
  }
  
  // Si pas assez de recommandations, ajouter des génériques
  if (priorityRecommendations.length < 3) {
    priorityRecommendations.push('Envisagez d\'implémenter une politique de sécurité globale pour le développement');
    priorityRecommendations.push('Mettez en place des tests de sécurité automatisés dans votre CI/CD');
    priorityRecommendations.push('Formez votre équipe aux bonnes pratiques de sécurité en Node.js');
  }
  
  // Limiter à 5 recommandations max
  for (const rec of priorityRecommendations.slice(0, 5)) {
    addRecommendation(rec);
  }
  
  // Sections détaillées - une par type d'analyse
  
  // Vulnérabilités des dépendances
  doc.addPage();
  addHeader('1. Vulnérabilités des Dépendances', { underline: true });
  
  if (results.dependencies && results.dependencies.audit && results.dependencies.audit.vulnerabilities) {
    const vuln = results.dependencies.audit.vulnerabilities;
    
    addParagraph(`L'analyse a détecté des vulnérabilités dans les dépendances de votre projet:`);
    
    try {
      const chartImage = generateChartImage({
        'Critique': vuln.critical || 0,
        'Élevé': vuln.high || 0,
        'Moyen': vuln.moderate || 0,
        'Faible': vuln.low || 0,
        'Info': vuln.info || 0
      }, 'pie', 'Répartition des vulnérabilités par niveau');
      
      doc.image(chartImage, {
        fit: [300, 200],
        align: 'center'
      });
    } catch (err) {
      console.error('Error generating chart:', err);
    }
    
    if (results.dependencies.audit.details && results.dependencies.audit.details.length > 0) {
      addSubHeader('Détails des vulnérabilités');
      
      for (const issue of results.dependencies.audit.details.slice(0, 10)) { // Limiter à 10 pour éviter un rapport trop long
        doc.fontSize(12)
           .fillColor(colors.text)
           .font('Helvetica-Bold')
           .text(`• ${issue.name}`, { continued: true })
           .font('Helvetica')
           .text(` (${issue.severity.toUpperCase()})`, { underline: false });
        
        doc.fontSize(10)
           .text(`  Title: ${issue.title}`)
           .text(`  Versions vulnérables: ${issue.vulnerable_versions}`);
        
        if (issue.recommendation) {
          doc.fillColor(colors.highlight)
             .text(`  📝 ${issue.recommendation}`)
             .fillColor(colors.text);
        }
        
        if (issue.url) {
          doc.fillColor(colors.info)
             .text(`  Plus d'informations: ${issue.url}`)
             .fillColor(colors.text);
        }
        
        doc.moveDown(0.5);
      }
      
      if (results.dependencies.audit.details.length > 10) {
        addParagraph(`... et ${results.dependencies.audit.details.length - 10} autres vulnérabilités.`);
      }
    }
    
    addSubHeader('Recommandations');
    addRecommendation('Exécutez régulièrement npm audit et mettez à jour les dépendances vulnérables');
    addRecommendation('Utilisez npm audit fix pour les mises à jour automatiques des dépendances');
    addRecommendation('Envisagez d\'utiliser Snyk ou Dependabot pour la surveillance continue des dépendances');
    addRecommendation('Vérifiez les versions vulnérables et mettez à jour vers des versions sécurisées');
  } else {
    addParagraph('Aucune vulnérabilité détectée dans les dépendances. Continuez à maintenir des dépendances à jour.');
  }
  
  // Secrets détectés
  doc.addPage();
  addHeader('2. Secrets et Informations Sensibles', { underline: true });
  
  if (results.secrets && results.secrets.secrets && results.secrets.secrets.length > 0) {
    addParagraph(`L'analyse a détecté ${results.secrets.secrets.length} fuites potentielles d'informations sensibles dans votre code:`);
    
    for (const secret of results.secrets.secrets) {
      addIssue(secret);
    }
    
    // Environnment variables analysis
    if (results.secrets.environmentVariables) {
      const env = results.secrets.environmentVariables;
      
      if (env.missing && env.missing.length > 0) {
        addSubHeader('Variables d\'environnement manquantes');
        addParagraph(`Les variables d'environnement suivantes sont utilisées dans le code mais n'ont pas été trouvées dans les fichiers .env:`);
        
        for (const variable of env.missing) {
          doc.fontSize(12)
             .fillColor(colors.high)
             .text(`• ${variable}`)
             .moveDown(0.2);
        }
      }
    }
  } else {
    addParagraph('Aucun secret ou information sensible détecté dans le code. Bonne pratique!');
  }
  
  addSubHeader('Recommandations pour la gestion des secrets');
  addRecommendation('Utilisez des variables d\'environnement pour stocker toutes les informations sensibles');
  addRecommendation('Créez un fichier .env.example sans valeurs sensibles pour le versionnement');
  addRecommendation('N\'incluez jamais les fichiers .env dans le contrôle de version (via .gitignore)');
  addRecommendation('Envisagez d\'utiliser un gestionnaire de secrets comme Vault ou AWS Secrets Manager');
  addRecommendation('Rotez régulièrement les clés API et tokens');
  
  // Authentification et autorisation
  if (results.auth) {
    doc.addPage();
    addHeader('3. Authentification et Autorisation', { underline: true });
    
    if (results.auth.auth && results.auth.auth.length > 0) {
      addSubHeader('Problèmes d\'authentification');
      for (const issue of results.auth.auth) {
        addIssue(issue);
      }
    }
    
    if (results.auth.authorization && results.auth.authorization.length > 0) {
      addSubHeader('Problèmes d\'autorisation');
      for (const issue of results.auth.authorization) {
        addIssue(issue);
      }
    }
    
    if (results.auth.packages) {
      if (results.auth.packages.installed.length > 0) {
        addSubHeader('Packages de sécurité installés');
        for (const pkg of results.auth.packages.installed) {
          doc.fontSize(12)
             .fillColor(colors.success)
             .text(`• ${pkg}`)
             .moveDown(0.2);
        }
      }
      
      if (results.auth.packages.recommended.length > 0) {
        addSubHeader('Packages recommandés');
        for (const pkg of results.auth.packages.recommended) {
          doc.fontSize(12)
             .fillColor(colors.info)
             .text(`• ${pkg}`)
             .moveDown(0.2);
        }
      }
    }
  }
  
  // Générer des sections pour les autres analyses...
  // On pourrait ajouter des sections similaires pour les autres types d'analyses
  
  // Section finale avec les recommandations générales
  doc.addPage();
  addHeader('Recommandations Générales', { underline: true });
  
  const generalRecommendations = [
    'Maintenez toutes les dépendances à jour et surveillez les vulnérabilités',
    'Implémentez tous les middlewares de sécurité essentiels',
    'Validez et sanitisez toutes les entrées utilisateur',
    'Stockez les secrets dans des variables d\'environnement',
    'Utilisez HTTPS partout, y compris en développement',
    'Configurez correctement CORS pour limiter les origines',
    'Implémentez le rate limiting pour prévenir les attaques par force brute',
    'Validez les autorisations à chaque niveau de l\'application',
    'Utilisez des tokens JWT avec expiration et signatures sécurisées',
    'Mettez en place des tests de sécurité automatisés',
    'Effectuez des audits de sécurité réguliers',
    'Formez votre équipe aux bonnes pratiques de sécurité'
  ];
  
  for (const rec of generalRecommendations) {
    addRecommendation(rec);
  }
  
  // Pied de page
  doc.fontSize(10)
     .fillColor(colors.text)
     .text('Rapport généré par NodeSecureScanner - ' + new Date().toLocaleString(), {
       align: 'center'
     });

  // Ajouter la signature de l'auteur
  doc.moveDown(1)
     .fontSize(10)
     .fillColor(colors.highlight)
     .text('NodeSecureScanner développé par TROPENOU DOGBE Yizreel Yao', {
       align: 'center'
     })
     .fontSize(9)
     .text('email: elomtropenoudogbe@gmail.com', {
       align: 'center'
     });

  // Finaliser le document
  doc.end();
  console.log('\n📄 Rapport PDF généré :', filename);
  
  return filename;
};
