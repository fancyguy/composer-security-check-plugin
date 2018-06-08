<?php

namespace FancyGuy\Composer\SecurityCheck;

use Composer\Composer;
use Composer\Factory;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\Capable;
use Composer\Plugin\CommandEvent;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Script\Event as ScriptEvent;
use Composer\Script\ScriptEvents;
use FancyGuy\Composer\SecurityCheck\Checker\DefaultChecker;
use FancyGuy\Composer\SecurityCheck\Util\DiagnosticsUtility;

class SecurityCheckPlugin implements PluginInterface, Capable, EventSubscriberInterface
{

    const VERSION = '1.0';

    public static function getSubscribedEvents()
    {
        return array(
            // handle no-audit option
            PluginEvents::PRE_COMMAND_RUN => array(
                array('onPreCommandRunEvent', 1),
            ),
            // diagnose, show, validate
            PluginEvents::COMMAND => array(
                array('onCommandEvent'),
            ),
            // status
            ScriptEvents::POST_STATUS_CMD => array(
                array('onScriptEvent')
            ),
            // install, remove, require, update
            ScriptEvents::POST_INSTALL_CMD => array(
                array('onScriptEvent'),
            ),
            ScriptEvents::POST_UPDATE_CMD => array(
                array('onScriptEvent'),
            ),
        );
    }

    private $io;

    protected function getIO()
    {
        return $this->io;
    }

    public function activate(Composer $composer, IOInterface $io)
    {
        $this->io = $io;
    }

    public function getCapabilities()
    {
        return array(
            'Composer\Plugin\Capability\CommandProvider' => 'FancyGuy\Composer\SecurityCheck\Command\AuditCommandProvider',
        );
    }

    public function onCommandEvent(CommandEvent $event)
    {
        switch ($event->getCommandName()) {
            case 'diagnose':
                $this->onDiagnose();
                break;
            case 'show':
            case 'validate':
                $this->auditDependencies();
                break;
        }
    }

    // TODO: Figure out how to manipulate the input definition
    public function onPreCommandRunEvent(PreCommandRunEvent $event)
    {
    }

    public function onScriptEvent(ScriptEvent $event)
    {
        $this->auditDependencies();
    }

    protected function onDiagnose()
    {
        $diagnosticsUtil = new DiagnosticsUtility($this->getIO());
        $diagnosticsUtil->diagnose();
    }

    protected function auditDependencies()
    {
        $checker = new DefaultChecker();
        $io = $this->getIO();

        $composerFile = Factory::getComposerFile();

        try {
            $vulnerabilities = $checker->check($composerFile);
        } catch (ExceptionInterface $e) {
            $io->write('<error>%s</error>', $e->getMessage());

            return;
        }

        if (!is_array($vulnerabilities)) {
            if ($io->isVerbose()) {
                $io->write('<comment>Security Checker service returned garbage.</comment>');
            }

            return;
        }

        if ($count = count($vulnerabilities)) {
            $status = '[CRITICAL] ';
            $style = 'fg=red';
        } else {
            $status = '';
            $style = 'info';
        }

        $io->write(sprintf('<%s>%s%s %s known vulnerabilities.</>', $style, $status, 0 === $count ? 'No' : $count, 1 === $count ? 'package has' : 'packages have'));
    }
}
