<?php

namespace Bitty\Security\Context;

use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Context\ContextMapInterface;
use Bitty\Security\User\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

class ContextMap implements ContextMapInterface
{
    /**
     * @var ContextInterface[]
     */
    protected $contexts = [];

    /**
     * {@inheritDoc}
     */
    public function add(ContextInterface $context): void
    {
        $this->contexts[] = $context;
    }

    /**
     * {@inheritDoc}
     */
    public function getUser(ServerRequestInterface $request): ?UserInterface
    {
        // Find user based on request.
        foreach ($this->contexts as $context) {
            if ($context->isShielded($request)) {
                return $context->get('user');
            }
        }

        // Request is not secured.
        // Find user from default context.
        foreach ($this->contexts as $context) {
            if ($context->isDefault()) {
                return $context->get('user');
            }
        }

        // No default context set.
        // Find user from first available context.
        $default = reset($this->contexts);
        if ($default) {
            return $default->get('user');
        }

        return null;
    }
}
