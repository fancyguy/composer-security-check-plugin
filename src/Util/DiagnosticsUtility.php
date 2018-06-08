<?php

namespace FancyGuy\Composer\SecurityCheck\Util;

use Composer\IO\IOInterface;
use FancyGuy\Composer\SecurityCheck\Checker\DefaultChecker;

class DiagnosticsUtility
{
    public function __construct(IOInterface $io)
    {
        $this->io = $io;
    }

    public function getIO()
    {
        return $this->io;
    }

    public function diagnose()
    {
        $io = $this->getIO();

        $io->write('Checking connectivity to security checker service: ', false);
        $this->outputResult($this->checkService());
    }

    public function checkService()
    {
        $checker = new DefaultChecker();

        return $checker->testConnection();
    }

    protected function outputResult($result)
    {
        $io = $this->getIO();

        if (true === $result) {
            $io->write('<info>OK</info>');

            return;
        }

        $hadError = false;
        if (result instanceof \Exception) {
            $result = sprintf('<error>[%s] %s</error>', get_class($result), $result->getMessage());
        }

        if (!$result) {
            $hadError = true;
        } else {
            if (!is_array($result)) {
                $result = array($result);
            }
            foreach ($result as $message) {
                if (false !== strpos($message, '<error>')) {
                    $hadError = true;
                }
            }
        }

        // TODO: Figure out how to set the exit code for diagnose command
        if ($hadError) {
            $io->write('<error>FAIL</error>');
        } else {
            $io->write('<warning>WARNING</warning>');
        }

        if ($result) {
            foreach ($result as $message) {
                $io->write($message);
            }
        }
    }
}
