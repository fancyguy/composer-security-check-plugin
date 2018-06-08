<?php

namespace FancyGuy\Composer\SecurityCheck\Formatter;

use Symfony\Component\Console\Output\OutputInterface;

interface FormatterInterface
{

    /**
     * Displays a security report.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    $ht file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities);
}
