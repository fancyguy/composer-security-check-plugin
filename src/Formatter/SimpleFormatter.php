<?php

namespace FancyGuy\Composer\SecurityCheck\Formatter;

use Symfony\Component\Console\Helper\FormatterHelper;
use Symfony\Component\Console\Output\OutputInterface;

class SimpleFormatter implements FormatterInterface
{

    const FORMAT = 'simple';

    protected $formatter;

    public function __construct(FormatterHelper $formatter)
    {
        $this->formatter = $formatter;
    }

    /**
     * {@inheritdoc}
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        $output->writeln(sprintf('Composer Security Check Report: <comment>%s</>', realpath($lockFilePath)));

        if ($count = count($vulnerabilities)) {
            $status = 'CRITICAL';
            $style = 'error';
        } else {
            $status = 'OK';
            $style = 'info';
        }

        $output->writeln(sprintf('<%s>[%s] %d %s known vulnerabilities</>', $style, $status, $count, 1 === $count ? 'package has' : 'packages have'));

        if (0 !== $count) {
            $output->write("\n");

            foreach ($vulnerabilities as $dependency => $issues) {
                $dependencyFullName = sprintf('%s (%s)', $dependency, $issues['version']);
                $output->writeln(sprintf("<info>%s\n%s</>\n", $dependencyFullName, str_repeat('-', strlen($dependencyFullName))));

                foreach ($issues['advisories'] as $issue => $details) {
                    $output->write(' * ');
                    if ($details['cve']) {
                        $output->write(sprintf('<comment>%s: </>', $details['cve']));
                    }
                    $output->writeln($details['title']);

                    if ('' !== $details['link']) {
                        $output->writeln('    '.$details['link']);
                    }

                    $output->writeln('');
                }
            }
        }
    }
}
