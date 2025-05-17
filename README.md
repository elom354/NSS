# NodeSecureScanner

![NodeSecureScanner Logo](https://img.shields.io/badge/NodeSecure-Scanner-green)

Un outil d'analyse de sécurité complet pour les applications Node.js qui détecte les vulnérabilités et génère des rapports détaillés.

## 📚 Guide d'implémentation et d'utilisation

### Prérequis

- Node.js (version 14.0.0 ou supérieure)
- npm ou yarn

### Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/elom354/NSS
cd NodeSecureScanner
```

2. Installez les dépendances :
```bash
npm install
```

### Utilisation

Pour scanner un projet Node.js :

```bash
node index.js <chemin-vers-le-projet>
```

Par exemple :
```bash
node index.js C:/path/to/your/nodejs/project
```

Le scanner analysera le projet et générera un rapport PDF dans le dossier `reports/`.

### Options

Pour l'instant, l'outil accepte uniquement un argument : le chemin vers le projet à analyser.

## 🛡️ Description du projet

NSS ou NodeSecureScanner est un outil d'analyse statique de code conçu pour détecter automatiquement les problèmes de sécurité courants dans les applications Node.js. Il s'exécute localement sur votre machine et fournit une évaluation complète de la sécurité avec des recommandations personnalisées.

### Pourquoi NodeSecureScanner ?

La sécurité est souvent négligée dans le développement web, particulièrement dans les applications Node.js où les équipes se concentrent sur les fonctionnalités plutôt que sur les aspects sécuritaires. NodeSecureScanner aide à :

- **Détecter rapidement** les problèmes de sécurité sans expertise approfondie
- **Éduquer les développeurs** sur les bonnes pratiques de sécurité
- **Améliorer la qualité du code** en recommandant des corrections spécifiques
- **Prévenir les attaques** avant qu'elles ne se produisent
- **Générer des rapports détaillés** pour les audits et la documentation

## ✨ Fonctionnalités

NodeSecureScanner effectue des analyses approfondies dans plusieurs domaines clés :

### 1. Analyse des dépendances
- Détection des vulnérabilités connues dans les packages npm
- Identification des dépendances obsolètes
- Vérification des licences de packages

### 2. Détection de secrets exposés
- Recherche de clés API, tokens, et mots de passe dans le code
- Vérification de l'utilisation sécurisée des variables d'environnement
- Identification des informations sensibles exposées

### 3. Sécurité du serveur web
- Analyse des configurations de middlewares Express
- Vérification des configurations CORS
- Détection des problèmes de rate limiting

### 4. Sécurité des données
- Détection des vulnérabilités d'injection SQL/NoSQL
- Analyse de validation des entrées utilisateur
- Vérification des problèmes XSS potentiels

### 5. Authentification et autorisation
- Vérification des mécanismes d'authentification
- Détection des problèmes d'autorisation
- Analyse des configurations de tokens JWT

### 6. Autres vulnérabilités
- Détection des vulnérabilités CSRF
- Analyse de la sécurité des cookies
- Vérification des bonnes pratiques générales

## 📊 Rapport de sécurité

À la fin de l'analyse, NodeSecureScanner génère un rapport PDF détaillé qui inclut :

- Un score global de sécurité
- Un résumé exécutif des problèmes détectés
- Des visualisations graphiques des vulnérabilités
- Des détails techniques sur chaque problème trouvé
- Des recommandations concrètes pour résoudre les problèmes

## 🧰 Structure du projet

```
NodeSecureScanner/
├── index.js                # Point d'entrée principal
├── utils/                  # Utilitaires génériques
│   └── fileUtils.js        # Fonctions de manipulation de fichiers
├── scanner/                # Modules d'analyse
│   ├── dependencyScanner.js    # Analyse des dépendances
│   ├── secretScanner.js        # Détection de secrets
│   ├── middlewareScanner.js    # Analyse des middlewares
│   ├── corsScanner.js          # Vérification CORS
│   ├── rateLimitScanner.js     # Analyse rate limiting
│   ├── sqlInjectionScanner.js  # Détection injections SQL/NoSQL
│   ├── authScanner.js          # Analyse d'authentification
│   ├── inputValidationScanner.js # Validation des entrées
│   ├── csrfScanner.js          # Détection CSRF
│   ├── cookieScanner.js        # Sécurité des cookies
│   └── reportGenerator.js      # Génération de rapports PDF
└── reports/                # Dossier des rapports générés
```

## 🚀 Prochaines étapes

- Ajout d'une interface utilisateur web
- Intégration avec les pipelines CI/CD
- Support pour d'autres frameworks JavaScript
- Scan en temps réel pendant le développement
- Personnalisation des règles d'analyse
- Intégration de l'IA pour les analyses automatisées

## 📄 Licence

Ce projet est sous licence MIT.

## 👨‍💻 Auteur

NodeSecureScanner développé par TROPENOU DOGBE Yizreel Yao.
Email: elomtropenoudogbe@gmail.com 