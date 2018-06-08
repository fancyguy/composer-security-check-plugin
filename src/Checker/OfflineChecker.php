<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

use Composer\Package\Package;
use Composer\Package\Version\VersionParser;
use Composer\Repository\ArrayRepository;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\MultiConstraint;
use FancyGuy\Composer\SecurityCheck\Exception\RuntimeException;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Yaml\Parser;

class OfflineChecker extends BaseChecker
{

    protected $databasePath;

    protected $output;

    protected $parser;

    public function __construct($databasePath, OutputInterface $output = null)
    {
        $this->databasePath = $databasePath;

        $this->output = null === $output ? new NullOutput : $output;

        $this->parser = new Parser();
    }

    /**
     * {@inheritdoc}
     */
    protected function doCheck($lock)
    {
        $lockContents = json_decode($this->getLockContents($lock), true);

        $vulnerabilities = array();

        $versionParser = new VersionParser();

        $packages = array();
        foreach (array('packages', 'packages-dev') as $key) {
            $data = $lockContents[$key];
            foreach ($data as $pkgData) {
                $normalizedVersion = $versionParser->normalize($pkgData['version']);
                $packages[] = new Package($pkgData['name'], $normalizedVersion, $pkgData['version']);
            }
        }
        unset($lockContents);

        $packageRepository = new ArrayRepository($packages);

        $messages = array();
        $vulnerabilities = array();

        $dbPath = $this->databasePath;

        $advisoryFilter = function (\SplFileInfo $file) use ($dbPath) {
            if ($file->isFile() && $dbPath === $file->getPath()) {
                return false;
            }

            if ($file->isDir()) {
                if ($dbPath.DIRECTORY_SEPARATOR.'vendor' === $file->getPathname()) {
                    return false;
                }

                $dirName = $file->getFilename();
                if ('.' === $dirName[0]) {
                    return false;
                }
            }

            return true;
        };

        $dir = new \RecursiveIteratorIterator(new \RecursiveCallbackFilterIterator(new \RecursiveDirectoryIterator($dbPath), $advisoryFilter));

        $progress = new ProgressBar($this->output, count(iterator_to_array($dir)));
        $progress->start();

        foreach ($dir as $file) {
            if (!$file->isFile()) {
                $progress->advance();

                continue;
            }

            $path = str_replace($this->databasePath.DIRECTORY_SEPARATOR, '', $file->getPathname());

            if ('yaml' !== $file->getExtension()) {
                $messages[$path][] = 'The file extension should be ".yaml"';
                continue;
            }

            try {
                $data = $this->parser->parse(file_get_contents($file));

                if (!isset($data['reference'])) {
                    $messages[$path][] = 'The entry does not have a reference package.';
                    $progress->advance();

                    continue;
                }

                // FIXME: This will break when other reference types are added
                if (0 !== strpos($data['reference'], 'composer://')) {
                    $messages[$path][] = 'Reference does not start with "composer://"';
                    $progress->advance();

                    continue;
                }

                $composerPackage = substr($data['reference'], 11);

                if (!isset($data['branches'])) {
                    $progress->advance();

                    continue;
                }

                if (!is_array($data['branches'])) {
                    $messages[$path][] = '"branches" is expected to be an array.';
                    $progress->advance();

                    continue;
                }

                $supportedOperators = Constraint::getSupportedOperators();

                foreach ($data['branches'] as $name => $branch) {
                    if (!isset($branch['versions'])) {
                        $messages[$path][] = sprintf('Key "versions" is not set for branch "%s".', $name);
                    } elseif (!is_array($branch['versions'])) {
                        $messages[$path][] = sprintf('"versions" is expected to be an array for branch "%s".', $name);
                    } else {
                        $constraints = array();
                        foreach ($branch['versions'] as $version) {
                            $op = null;
                            foreach ($supportedOperators as $o) {
                                if (0 === strpos($version, $o)) {
                                    $op = $o;
                                    break;
                                }
                            }

                            if (null === $op) {
                                $messages[$path][] = sprintf('Version "%s" does not contain a supported operator.', $version);
                                continue;
                            }

                            $ver = substr($version, strlen($op));
                            $constraints[] = new Constraint($op, $ver);
                        }
                        $affectedConstraint = new MultiConstraint($constraints);
                        $affectedPackage = $packageRepository->findPackage($composerPackage, $affectedConstraint);
                        if ($affectedPackage) {
                            $vulnerabilities[$composerPackage] = isset($vulnerabilities[$composerPackage]) ? $vulnerabilities[$composerPackage] : array(
                                'version' => $affectedPackage->getPrettyVersion(),
                                'advisories' => array(),
                            );
                            $vulnerabilities[$composerPackage]['advisories'][$path] = array(
                                'title' => isset($data['title']) ? $data['title'] : '',
                                'link' => isset($data['link']) ? $data['link'] : '',
                                'cve' => isset($data['cve']) ? $data['cve'] : '',
                            );
                        }
                    }
                }
            } catch (ParseException $e) {
                $messages[$path][] = sprintf('YAML is not valid (%s).', $e->getMessage());
            }

            $progress->advance();
        }

        $progress->finish();

        $this->output->newLine();

        ksort($vulnerabilities);

        return array((int) count($vulnerabilities), $vulnerabilities);
    }
}
