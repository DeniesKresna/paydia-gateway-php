FROM php:7-fpm-alpine

WORKDIR /var/www/html
COPY src/ /var/www/html
