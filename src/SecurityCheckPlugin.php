<?php

namespace FancyGuy\Composer\SecurityCheck;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\Capable;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;

class SecurityCheckPlugin implements PluginInterface, Capable, EventSubscriberInterface
{

    const VERSION = '1.0';

    public static function getSubscribedEvents()
    {
        return array(
            PluginEvents::PRE_COMMAND_RUN => array(
                array('onPreCommandRun', 1)
            ),
        );
    }

    public function activate(Composer $composer, IOInterface $io)
    {
    }

    public function getCapabilities()
    {
        return array(
            'Composer\Plugin\Capability\CommandProvider' => 'FancyGuy\Composer\SecurityCheck\Command\AuditCommandProvider',
        );
    }

    public function onPreCommandRun(PreCommandRunEvent $event)
    {
        
    }
}
