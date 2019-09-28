<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

use FancyGuy\Composer\SecurityCheck\Exception\RuntimeException;

abstract class HttpChecker extends BaseChecker implements HttpCheckerInterface
{

    protected $endpoint = HttpCheckerInterface::DEFAULT_ENDPOINT;
    protected $timeout = HttpCheckerInterface::DEFAULT_TIMEOUT;

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     * {@inheritdoc}
     */
    public function setEndpoint($endpoint) {
        $this->endpoint = $endpoint;
    }

    /**
     * {@inheritdoc}
     */
    protected function doCheck($lock)
    {
        $certFile = $this->getCertFile();

        list($headers, $body) = $this->doHttpCheck($lock, $certFile);

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        return array((int) $matches[1], json_decode($body, true));
    }

    public function testConnection()
    {
        $certFile = $this->getCertFile();

        $lockContents = array(
            'packages' => array(),
            'packages-dev' => array(),
        );

        $tmplock = tempnam(sys_get_temp_dir(), 'composer_securitycheck_diag');
        $handle = fopen($tmplock, 'w');
        fwrite($handle, json_encode($lockContents));
        fclose($handle);

        list($headers, $body) = $this->doHttpCheck($tmplock, $certFile);

        unlink($tmplock);

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        return true;
    }

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    abstract protected function doHttpCheck($lock, $certFile);

    private function getCertFile()
    {
        $certFile = __DIR__.'/../../res/security.symfony.com.crt';

        return $certFile;
    }
}
