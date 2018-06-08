<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

use FancyGuy\Composer\SecurityCheck\Exception\RuntimeException;

interface CheckerInterface
{

    /**
     * Checks a composer lock file.
     *
     * @param string $lock The path to the composer.lock file
     *
     * @return array An array of vulnerabilities
     *
     * @throws RuntimeException When the lock file does not exist
     */
    public function check($lock);

    public function getLastVulnerabilityCount();
}

