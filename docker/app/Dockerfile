FROM php:7.3-fpm

ARG APP_ENV='prod'
ENV COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update -y && \
    apt-get install -y gcc make autoconf libc-dev pkg-config zlib1g-dev g++ gnupg2 zip unzip wget gpg libpq-dev \
    libxslt-dev libmagickwand-dev libpng-dev libjpeg-dev libfreetype6 libfreetype6-dev git libzip-dev libgmp-dev \
    libxml2-dev libicu-dev tzdata libc-client-dev libkrb5-dev

RUN docker-php-ext-install pdo_pgsql pdo_mysql bcmath zip mbstring opcache exif calendar gettext \
    gmp mysqli soap sockets shmop sysvmsg sysvsem sysvshm xsl wddx intl gd

RUN docker-php-ext-configure imap --with-kerberos --with-imap-ssl && docker-php-ext-install -j$(nproc) imap

RUN if [ ${APP_ENV} = 'dev' ]; then \
    pecl install xdebug-2.9.2 \
    && docker-php-ext-enable xdebug \
;fi

COPY ./docker/app/config.ini $PHP_INI_DIR/conf.d/config.ini
COPY ./docker/app/www.conf /usr/local/etc/php-fpm.d/www.conf

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

ARG TIMEZONE="UTC"
RUN echo ${TIMEZONE} > /etc/timezone \
    && rm /etc/localtime \
    && ln -snf /usr/share/zoneinfo/${TIMEZONE} /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && apt-get clean \
    && echo "date.timezone = ${TIMEZONE}" >> /usr/local/etc/php/conf.d/tz.ini

WORKDIR /var/www/leads
CMD ["php-fpm"]