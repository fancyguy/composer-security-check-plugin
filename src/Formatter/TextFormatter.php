<?php

namespace FancyGuy\Composer\SecurityCheck\Formatter;

use Symfony\Component\Console\Helper\FormatterHelper;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class TextFormatter implements FormatterInterface
{

    const FORMAT = 'text';

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
        $output = new SymfonyStyle(new ArrayInput(array()), $output);
        $output->title('Composer Security Check Report');

        $output->writeln(sprintf('<fg=default;bg=default> // </>Checked file: <comment>%s</>', realpath($lockFilePath)));

        if ($count = count($vulnerabilities)) {
            $output->error(sprintf('%d packages have known vulnerabilities.', $count));
        } else {
            $output->success('No packages have known vulnerabilities.');
        }

        if (0 !== $count) {
            foreach ($vulnerabilities as $dependency => $issues) {
                $output->section(sprintf('%s (%s)', $dependency, $issues['version']));

                $details = array_map(function ($value) {
                    return sprintf("<info>%s</>: %s\n    %s", $value['cve'] ?: '(no CVE ID)', $value['title'], $value['link']);
                }, $issues['advisories']);

                $output->listing($details);
            }
        }

        $output->note('This checker can only detect vulnerabilities that are referenced in the SensioLabs security advisories database.');
    }
}
