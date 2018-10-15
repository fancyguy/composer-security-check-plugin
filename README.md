# Security Check Plugin for Composer

For global install:

    composer global require fancyguy/composer-security-check-plugin

For project install:

    composer require fancyguy/composer-security-check-plugin

Run these commands to see some sample behavior:

    mkdir insecure-project
    cd insecure-project
    composer init --name="insecure/project" --description="insecure project" -l MIT -n
    composer require symfony/symfony:2.5.2
    composer audit
    composer audit --format=simple
    composer audit --format=json
    composer validate
    composer require symfony/symfony --update-with-all-dependencies
    composer audit

By default this tool uses the checks from https://github.com/FriendsOfPHP/security-advisories. 
You can supply a local version of this repo using

    composer audit --audit-db /path/to/security-advisories

Inspired on: https://github.com/sensiolabs/security-checker 

Alternative: https://github.com/Roave/SecurityAdvisories
