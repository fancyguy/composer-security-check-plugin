<?php

namespace FancyGuy\Composer\SecurityCheck\Command;

use Composer\Factory;
use Composer\Command\BaseCommand;
use FancyGuy\Composer\SecurityCheck\Checker\DefaultChecker;
use FancyGuy\Composer\SecurityCheck\Checker\OfflineChecker;
use FancyGuy\Composer\SecurityCheck\Exception\ExceptionInterface;
use FancyGuy\Composer\SecurityCheck\Formatter\JsonFormatter;
use FancyGuy\Composer\SecurityCheck\Formatter\SimpleFormatter;
use FancyGuy\Composer\SecurityCheck\Formatter\TextFormatter;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class AuditCommand extends BaseCommand
{

    protected function configure()
    {
        $this
            ->setName('audit')
            ->setDefinition(array(
                new InputOption('audit-db', '', InputOption::VALUE_REQUIRED, 'The path to the advisory database'),
                new InputOption('format', '', InputOption::VALUE_REQUIRED, 'The output format', 'text'),
                new InputOption('endpoint', '', InputOption::VALUE_REQUIRED, 'The security checker server URL'),
                new InputOption('timeout', '', InputOption::VALUE_REQUIRED, 'The HTTP timeout in seconds'),
            ))
            ->setDescription('Checks security issues in your project dependencies')
            ->setHelp(<<<EOF
The <info>%command.name%</info> command looks for security issues in the
project dependencies:

<info>%command.full_name%</info>
EOF
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if ($databasePath = $input->getOption('audit-db')) {
            $checker = new OfflineChecker($databasePath, new SymfonyStyle($input, $output));
        } else {
            $checker = new DefaultChecker();

            if ($endpoint = $input->getOption('endpoint')) {
                $checker->setEndpoint($endpoint);
            }

            if ($timeout = $input->getOption('timeout')) {
                $checker->setTimeout($timeout);
            }
        }

        $composerFile = Factory::getComposerFile();

        try {
            $vulnerabilities = $checker->check($composerFile);
        } catch (ExceptionInterface $e) {
            $output->writeln($this->formatError($e->getMessage()));

            return 1;
        }

        switch ($input->getOption('format')) {
            case JsonFormatter::FORMAT:
                $formatter = new JsonFormatter();
                break;
            case SimpleFormatter::FORMAT:
                $formatter = new SimpleFormatter($this->getHelperSet()->get('formatter'));
                break;
            case TextFormatter::FORMAT:
            default:
                $formatter = new TextFormatter($this->getHelperSet()->get('formatter'));
        }

        if (!is_array($vulnerabilities)) {
            $output->writeln($this->formatError('Security Checker service returned garbage.'));

            return 127;
        }

        $formatter->displayResults($output, $composerFile, $vulnerabilities);

        if ($checker->getLastVulnerabilityCount() > 0) {
            return 1;
        }
    }

    private function formatError($error) {
        $this->getHelperSet()->get('formatter')->formatBlock($error, 'error', true);
    }
}
