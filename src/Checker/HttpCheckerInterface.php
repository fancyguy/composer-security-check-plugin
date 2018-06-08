<?php

namespace FancyGuy\Composer\SecurityCheck\Checker;

interface HttpCheckerInterface extends CheckerInterface
{

    /**
     * Sets the HTTP timeout in seconds
     *
     * @param string $timeout The HTTP timeout in seconds
     */
    public function setTimeout($timeout);

    /**
     * Sets the security checker service URL
     *
     * @param string $endpoint The HTTP endpoint for the security checker service
     */
    public function setEndpoint($endpoint);
}
