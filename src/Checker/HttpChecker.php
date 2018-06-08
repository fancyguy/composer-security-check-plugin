<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

use FancyGuy\Composer\SecurityCheck\Exception\RuntimeException;

abstract class HttpChecker extends BaseChecker implements HttpCheckerInterface
{

    protected $endpoint = 'https://security.sensiolabs.org/check_lock';
    protected $timeout = 20;

    /**
     * {@inheritdoc}
     */
    public function setTimeout($tiemout)
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

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    abstract protected function doHttpCheck($lock, $certFile);

    private function getCertFile()
    {
        $certFile = __DIR__.'/../../res/security.sensiolabs.org.crt';

        return $certFile;
    }
}
