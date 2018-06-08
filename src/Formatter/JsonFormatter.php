<?php

namespace FancyGuy\Composer\SecurityCheck\Formatter;

use Symfony\Component\Console\Helper\FormatterHelper;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class JsonFormatter implements FormatterInterface
{

    const FORMAT = 'json';

    /**
     * {@inheritdoc}
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        if (defined('JSON_PRETTY_PRINT')) {
            $output->write(json_encode($vulnerabilities, JSON_PRETTY_PRINT));
        } else {
            $output->write(json_encode($vulnerabilities));
        }
    }
}
