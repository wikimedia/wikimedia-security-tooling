# multistage Dockerfile: php image, node image #

# php image #
FROM docker-registry.wikimedia.org/releng/ci-buster:latest AS php

# env vars
ENV DEBIAN_FRONTEND=noninteractive
ENV MW_INSTALL_PATH=/mnt/src/
ENV SECCHECK_VERSION=2.1.0
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8

# apt installs
USER root
RUN apt-get update && \
  apt-get install --yes \
  apt-transport-https \
  curl \
  jq \
  make \
  php7.3-cli \
  php7.3-dev \
  php7.3-zip \
  php7.3-curl \
  php7.3-dba \
  php7.3-gd \
  php7.3-mbstring \
  php-pear \
  php7.3-sqlite3 \
  php-xdebug \
  php7.3-xml \
  vim \
  --no-install-recommends && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

# install php-ast 1.0.3 from PEAR
RUN pecl install ast-1.0.3
RUN phpdismod xdebug
RUN echo "extension=ast" >> /etc/php/7.3/cli/php.ini

# install various dirs
RUN install -d -m 777 /srv/composer
RUN install --directory --mode 777 /opt/phan
RUN install --directory --mode 777 /opt/phpcs
RUN install --directory --mode 777 /opt/securitycheck
RUN install -d -m 777 /mnt/src

# install wm composer
RUN git clone --depth 1 https://gerrit.wikimedia.org/r/p/integration/composer.git/ \
  /srv/composer && \
  rm -rf /srv/composer/.git && \
  ln -s /srv/composer/vendor/bin/composer /usr/bin/composer
ENV COMPOSER_DISABLE_XDEBUG_WARN=1

USER nobody

# config phan for phan-taint-check (https://www.mediawiki.org/wiki/Phan-taint-check-plugin)
WORKDIR /opt/phan
RUN composer require \
  -n --no-plugins --no-scripts \
  mediawiki/phan-taint-check-plugin $SECCHECK_VERSION

# config phpcs (https://www.mediawiki.org/wiki/Continuous_integration/PHP_CodeSniffer)
# with: https://github.com/FloeDesignTechnologies/phpcs-security-audit
WORKDIR /opt/phpcs
RUN composer require \
  -n --no-plugins --no-scripts \
  mediawiki/mediawiki-codesniffer dev-master
RUN composer require pheromone/phpcs-security-audit
RUN sh vendor/pheromone/phpcs-security-audit/symlink.sh

# config symfony security-check (https://github.com/sensiolabs/security-checker)
WORKDIR /opt/securitycheck
RUN composer require \
  -n --no-plugins --no-scripts \
  sensiolabs/security-checker dev-master

# default to /src
WORKDIR /src


# node image #
FROM docker-registry.wikimedia.org/releng/node10 AS node

# install snyk
USER root
RUN npm install -g snyk

# install retire
RUN npm install -g retire

WORKDIR /src
