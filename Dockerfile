FROM php:8-apache

ADD src/ /var/www/html/

RUN a2enmod rewrite && a2enmod actions
