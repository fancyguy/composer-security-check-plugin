<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

abstract class BaseChecker implements CheckerInterface
{
    
    private $vulnerabilityCount;

    /**
     * {@inheritdoc}
     */
    public function check($lock)
    {
        if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
            $lock = $lock.'/composer.lock';
        } elseif (preg_match('/composer\.json$/', $lock)) {
            $lock = str_replace('composer.json', 'composer.lock', $lock);
        }

        if (!is_file($lock)) {
            throw new RuntimeException('Lock file does not exist.');
        }

        list($this->vulnerabilityCount, $vulnerabilities) = $this->doCheck($lock);

        return $vulnerabilities;
    }

    /**
     * {@inheritdoc}
     */
    public function getLastVulnerabilityCount()
    {
        return $this->vulnerabilityCount;
    }

    /**
     * @return An array of two items: the number of vulnerabilities and an array of the vulnerabilities
     */
    abstract protected function doCheck($lock);

    protected function getLockContents($lock)
    {
        $contents = json_decode(file_get_contents($lock), true);
        $packages = array('packages' => array(), 'packages-dev' => array());
        foreach (array('packages', 'packages-dev') as $key) {
            if (!is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = array(
                    'name' => $package['name'],
                    'version' => $package['version'],
                );
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }

        return json_encode($packages);
    }
}
