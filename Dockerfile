# ----------------------------------
# 1. Fase de construcción (Build)
# ----------------------------------

# Utilizamos una imagen base de PHP 8.2 con FPM y Alpine Linux para la construcción de la aplicación.
# Alpine es una distribución ligera, ideal para crear contenedores pequeños.
FROM php:8.2-fpm-alpine as builder

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /var/www/html

# Instalar las dependencias necesarias para la construcción de la aplicación.
# - bash, git, unzip, curl: herramientas básicas de línea de comandos
# - mariadb-client: cliente para interactuar con MariaDB
# - mariadb-connector-c-dev: bibliotecas de desarrollo para MariaDB
RUN apk update && \
    apk add --no-cache \
    bash \
    git \
    unzip \
    curl \
    mariadb-client \
    mariadb-connector-c-dev

# Instalar Composer, que es la herramienta de gestión de dependencias de PHP.
# Composer se descarga desde su sitio oficial y se instala en /usr/local/bin.
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Configurar variables de entorno para Composer
# - COMPOSER_ALLOW_SUPERUSER=1: permite ejecutar Composer como superusuario
# - COMPOSER_MEMORY_LIMIT=-1: desactiva el límite de memoria para Composer
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV COMPOSER_MEMORY_LIMIT=-1

# Copiar los archivos que contienen las dependencias de Composer (composer.json, composer.lock y symfony.lock).
# Estos archivos describen las dependencias que Composer instalará.
COPY composer.json composer.lock symfony.lock ./

# Ejecutar Composer para instalar las dependencias de la aplicación, excluyendo las de desarrollo (--no-dev).
# Esto se hace para optimizar la aplicación para producción.
RUN composer install --no-dev --no-interaction --optimize-autoloader --ignore-platform-reqs --no-scripts

# Crear directorios necesarios para caché y logs, y configurar permisos.
# - 777 para permitir que cualquier usuario tenga permisos de lectura, escritura y ejecución en estos directorios.
RUN mkdir -p var/cache var/log && \
    chmod -R 777 var

# ----------------------------------
# 2. Fase final (Runtime)
# ----------------------------------

# Utilizar una nueva imagen base de PHP 8.2 con FPM y Alpine para la fase de ejecución.
FROM php:8.2-fpm-alpine

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /var/www/html

# Instalar solo las dependencias críticas necesarias para ejecutar la aplicación en producción.
# - mariadb-client, mariadb-connector-c: cliente y librerías para interactuar con MariaDB.
# - docker-php-ext-install: instalar las extensiones PHP necesarias (pdo, pdo_mysql).
RUN apk update && \
    apk add --no-cache \
    bash \
    mariadb-client \
    mariadb-connector-c \
    && docker-php-ext-install pdo pdo_mysql \
    && docker-php-ext-enable pdo_mysql

# Crear un usuario y un grupo para la aplicación. Esto es una medida de seguridad para evitar que la aplicación
# se ejecute como root dentro del contenedor.
RUN addgroup -g 1000 symfony && \
    adduser -u 1000 -G symfony -D symfony

# Copiar las dependencias instaladas desde la fase de construcción (contenedor builder).
# Esto incluye las dependencias de Composer y las bibliotecas necesarias.
COPY --from=builder /var/www/html/vendor vendor/
COPY --from=builder /usr/local/bin/composer /usr/local/bin/composer

# Copiar el código de la aplicación, asegurándose de que los archivos sean propiedad del usuario "symfony".
COPY --chown=symfony:symfony . .

# Crear directorios necesarios para caché y logs, y configurar los permisos de propiedad y acceso.
# Se asegura de que el usuario "symfony" tenga permisos adecuados para escribir en estos directorios.
RUN mkdir -p var/cache var/log && \
    chown -R symfony:symfony var && \
    chmod -R 777 var

# Generar el archivo .env con configuraciones específicas para la producción.
# Esto incluye:
# - Configuración del entorno (APP_ENV)
# - URL de la base de datos (DATABASE_URL)
# - Claves JWT necesarias para la autenticación
# - Claves MAILER_DSN necesarias para el envio de correos
RUN echo "APP_ENV=prod" > .env && \
    echo "APP_DEBUG=false" >> .env && \
    echo "DATABASE_URL=${DATABASE_URL}" >> .env && \
    echo "JWT_SECRET_KEY=%kernel.project_dir%/config/jwt/private.pem" >> .env && \
    echo "JWT_PUBLIC_KEY=%kernel.project_dir%/config/jwt/public.pem" >> .env && \
    echo "JWT_PASSPHRASE=${JWT_PASSPHRASE}" >> .env && \
    echo "MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0" >> .env && \
    echo "MAILER_DSN=${MAILER_DSN}" >> .env

# Generar las claves JWT si no existen.
# Si las claves privadas y públicas no están presentes en el contenedor, se crean usando OpenSSL.
RUN mkdir -p config/jwt && \
    if [ ! -f config/jwt/private.pem ]; then \
    apk add --no-cache openssl && \
    openssl genpkey -out config/jwt/private.pem -aes256 -algorithm rsa -pkeyopt rsa_keygen_bits:4096 -pass pass:${JWT_PASSPHRASE} && \
    openssl pkey -in config/jwt/private.pem -out config/jwt/public.pem -pubout -passin pass:${JWT_PASSPHRASE}; \
    fi && \
    chown -R symfony:symfony config/jwt

# Cambiar al usuario "symfony" para que la aplicación se ejecute con privilegios limitados.
USER symfony

# Exponer el puerto 10000 para que la aplicación pueda ser accesible desde fuera del contenedor.
EXPOSE 10000

# Comando por defecto para iniciar el servidor PHP embebido, que sirve la aplicación en el puerto 10000.
CMD ["php", "-S", "0.0.0.0:10000", "-t", "public"]
