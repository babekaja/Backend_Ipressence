# Utiliser PHP CLI avec serveur intégré
FROM php:8.2-cli

# Installer extensions PDO MySQL
RUN docker-php-ext-install pdo pdo_mysql

# Copier ton projet
WORKDIR /app
COPY . /app

# Exposer le port attendu par Render
EXPOSE 10000

# Lancer le serveur intégré PHP
CMD ["php", "-S", "0.0.0.0:10000", "api.php"]
