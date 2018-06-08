<?php

namespace FancyGuy\Composer\SecurityCheck;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\Capable;
use Composer\Plugin\CommandEvent;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;
use FancyGuy\Composer\SecurityCheck\Util\DiagnosticsUtility;

class SecurityCheckPlugin implements PluginInterface, Capable, EventSubscriberInterface
{

    const VERSION = '1.0';

    private $io;

    public static function getSubscribedEvents()
    {
        return array(
            // handle no-audit option
            /*
            PluginEvents::PRE_COMMAND_RUN => array(
                array('onPreCommandRunEvent', 1),
            ),
            */
            // diagnose, show, validate
            PluginEvents::COMMAND => array(
                array('onCommandEvent'),
            ),
            // status
            /*
            ScriptEvents::POST_STATUS_CMD => array(
                array('onPostStatus')
            ),
            */
            // install, remove, require, update
            /*
            ScriptEvents::POST_INSTALL_CMD => array(
                array('onPostInstall'),
            ),
            ScriptEvents::POST_UPDATE_CMD => array(
                array('onPostUpdate'),
            ),
            */
        );
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
        }
    }

    // TODO: Figure out how to manipulate the input definition
    public function onPreCommandRunEvent(PreCommandRunEvent $event)
    {
        
    }

    public function onPostStatusCommandEvent()
    {
    }

    protected function getIO()
    {
        return $this->io;
    }

    protected function onDiagnose()
    {
        $diagnosticsUtil = new DiagnosticsUtility($this->getIO());
        $diagnosticsUtil->diagnose();
    }

    // FIXME: This needs implemented
    private function checkService()
    {
        return true;
    }
}
