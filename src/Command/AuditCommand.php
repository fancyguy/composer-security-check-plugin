<?php

namespace FancyGuy\Composer\SecurityCheck\Command;

use Composer\Command\BaseCommand;
use FancyGuy\Composer\SecurityCheck\Checker\DefaultChecker;
use FancyGuy\Composer\SecurityCheck\Checker\HttpCheckerInterface;
use FancyGuy\Composer\SecurityCheck\Exception\ExceptionInterface;
use FancyGuy\Composer\SecurityCheck\Formatter\JsonFormatter;
use FancyGuy\Composer\SecurityCheck\Formatter\SimpleFormatter;
use FancyGuy\Composer\SecurityCheck\Formatter\TextFormatter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AuditCommand extends BaseCommand
{

    private $checker;

    public function __construct(CheckerInterface $checker = null)
    {
        $this->checker = null === $checker ? new DefaultChecker() : $checker;

        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setName('audit')
            ->setDefinition(array(
                new InputArgument('lockfile', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock'),
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
        if ($this->checker instanceof HttpCheckerInterface) {
            if ($endpoint = $input->getOption('endpoint')) {
                $this->checker->setEndpoint($endpoint);
            }

            if ($timeout = $input->getOption('timeout')) {
                $this->checker->setTimeout($timeout);
            }
        }

        try {
            $vulnerabilities = $this->checker->check($input->getArgument('lockfile'));
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

        $formatter->displayResults($output, $input->getArgument('lockfile'), $vulnerabilities);

        if ($this->checker->getLastVulnerabilityCount() > 0) {
            return 1;
        }
    }

    private function formatError($error) {
        $this->getHelperSet()->get('formatter')->formatBlock($error, 'error', true);
    }
}
