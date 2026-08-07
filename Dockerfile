FROM php:8.3-cli-alpine

# System packages for collectors
RUN apk add --no-cache \
    curl \
    openssl \
    bind-tools \
    whois

# PHP extensions
RUN apk add --no-cache libxml2-dev && docker-php-ext-install dom

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader --no-interaction

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

CMD ["php", "-d", "max_execution_time=120", "-S", "0.0.0.0:8000", "-t", "public"]
