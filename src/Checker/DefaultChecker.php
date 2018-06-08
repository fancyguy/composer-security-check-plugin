<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

class DefaultChecker implements HttpCheckerInterface
{
    private $checker;

    public function __construct()
    {
        $this->checker = ('stream' === getenv('SENSIOLABS_SECURITY_CHECKER_TRANSPORT') || !function_exists('curl_init')) ? new FileGetContentsChecker() : new CurlChecker();
    }

    /**
     * {@inheritdoc}
     */
    public function check($lock)
    {
        return $this->checker->check($lock);
    }

    /**
     * {@inheritdoc}
     */
    public function getLastVulnerabilityCount()
    {
        return $this->checker->getLastVulnerabilityCount();
    }

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        return $this->checker->setTimeout($timeout);
    }

    /**
     * {@inheritdoc}
     */
    public function setEndpoint($endpoint)
    {
        return $this->checker->setEndpoint($endpoint);
    }
}
