<?php

namespace FancyGuy\Composer\SecurityCheck;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\Factory;
use Composer\IO\IOInterface;
use Composer\Installer\InstallationManager;
use Composer\Installer\InstallerEvent;
use Composer\Installer\InstallerEvents;
use Composer\Installer\NoopInstaller;
use Composer\Plugin\Capable;
use Composer\Plugin\CommandEvent;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Repository\InstalledArrayRepository;
use Composer\Repository\InstalledFilesystemRepository;
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
            // audit install candidates and possibly block installs
            InstallerEvents::POST_DEPENDENCIES_SOLVING => array(
                array('onInstallerEvent'),
            ),
            // status
            ScriptEvents::POST_STATUS_CMD => array(
                array('onScriptEvent'),
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

    private $composer;

    private $io;

    protected function getComposer()
    {
        return $this->composer;
    }

    protected function getIO()
    {
        return $this->io;
    }

    public function activate(Composer $composer, IOInterface $io)
    {
        $this->composer = $composer;
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
                $fileArgument = $event->getInput()->getArgument('file');
                $this->auditDependencies($fileArgument);
                break;
        }
    }

    // TODO: Figure out how to manipulate the input definition
    public function onPreCommandRunEvent(PreCommandRunEvent $event)
    {
    }

    public function onInstallerEvent(InstallerEvent $event)
    {
        $operations = $event->getOperations();
        if (!$operations) {
            // noop
            return;
        }

        $installedRepo = $event->getInstalledRepo();

        $isFilesystemInstall = false;
        foreach ($installedRepo->getRepositories() as $repo) {
            if ($repo instanceof InstalledFilesystemRepository) {
                $isFilesystemInstall = true;
                break;
            }
        }

        if (!$isFilesystemInstall) {
            // noop
            return;
        }

        $packages = array();
        foreach ($this->getComposer()->getRepositoryManager()->getLocalRepository()->getPackages() as $package) {
            $packages[(string) $package] = clone $package;
        }
        foreach ($packages as $key => $package) {
            if ($package instanceof AliasPackage) {
                $alias = (string) $package->getAliasOf();
                $packages[$key] = new AliasPackage($packages[$alias], $package->getVersion(), $package->getPrettyVersion());
            }
        }
        $localRepo = new InstalledArrayRepository($packages);

        $im = new InstallationManager();
        $im->addInstaller(new NoopInstaller);

        foreach ($operations as $operation) {
            // TODO: Fake passes like in Installer::extractDevPackages() break things
            //       Ideally we should have the local repository being used in the event
            //       For now, blindly ignore exceptions. The noop installer throws only
            //       when a package is not installed. We'll assume it is in another context
            try {
                $im->execute($localRepo, $operation);
            } catch (\Exception $e) {}
        }

        $locked = array();

        foreach ($localRepo->getCanonicalPackages() as $package) {
            if ($package instanceof AliasPackage) {
                continue;
            }

            $locked[] = array(
                'name' => $package->getPrettyName(),
                'version' => $package->getPrettyVersion(),
            );
        }

        $lockContents = array(
            'packages' => $locked,
            'packages-dev' => array(),
        );

        $tmplock = tempnam(sys_get_temp_dir(), 'composer_securitycheck_solver');
        $handle = fopen($tmplock, 'w');
        fwrite($handle, json_encode($lockContents));
        fclose($handle);

        $result = $this->auditDependencies($tmplock);
        unlink($tmplock);

        if (0 !== $result && $this->getIO()->isInteractive()) {
            $shouldInstall = $this->getIO()->askConfirmation('<comment>Would you like to continue installing?</> [<info>no</>]: ', false);
            if (!$shouldInstall && $this->getIO()->isInteractive()) {
                throw new \RuntimeException('Exiting due to vulnerabilities in target installtion.');
            }
        }

        unset($im);
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

    protected function auditDependencies($lockFile = null)
    {
        $checker = new DefaultChecker();
        $io = $this->getIO();

        $composerFile = null === $lockFile ? Factory::getComposerFile() : $lockFile;

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

        return $count;
    }
}
