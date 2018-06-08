<?php

namespace FancyGuy\Composer\SecurityCheck\Command;

use Composer\Plugin\Capability\CommandProvider;

class AuditCommandProvider implements CommandProvider
{

    public function getCommands()
    {
        return array(new AuditCommand);
    }
}
