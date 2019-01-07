<?php

namespace Bitty\Security\Context;

use Bitty\Security\Context\ContextMap;
use Bitty\Security\Context\ContextMapInterface;
use Interop\Container\ServiceProviderInterface;
use Psr\Container\ContainerInterface;

class ContextMapServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function getFactories(): array
    {
        return [];
    }

    /**
     * {@inheritDoc}
     */
    public function getExtensions(): array
    {
        return [
            'security.context' => function (ContainerInterface $container, ContextMapInterface $previous = null) {
                if ($previous) {
                    return $previous;
                }

                return new ContextMap();
            },
        ];
    }
}
