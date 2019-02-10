<?php

namespace Bitty\Security\Context;

use Bitty\Security\Context\ContextInterface;
use Psr\Http\Message\ServerRequestInterface;

class ContextCollection implements ContextInterface
{
    /**
     * @var \SplObjectStorage Collection of ContextInterface
     */
    private $contexts = null;

    /**
     * @var ContextInterface|null
     */
    private $activeContext = null;

    public function __construct()
    {
        $this->contexts = new \SplObjectStorage();
    }

    /**
     * Adds a context to the collection.
     *
     * @param ContextInterface $context
     */
    public function add(ContextInterface $context): void
    {
        $this->contexts->attach($context);
    }

    /**
     * Clears the active context, if one is set.
     */
    public function clearActiveContext(): void
    {
        $this->activeContext = null;
    }

    /**
     * {@inheritDoc}
     */
    public function isDefault(): bool
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            if ($context->isDefault()) {
                $this->activeContext = $context;

                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $name, $value): void
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            $context->set($name, $value);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $name, $default = null)
    {
        if ($this->activeContext) {
            return $this->activeContext->get($name, $default);
        }

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            $value = $context->get($name);
            if ($value !== null) {
                return $value;
            }
        }

        return $default;
    }

    /**
     * {@inheritDoc}
     */
    public function remove(string $name): void
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            $context->remove($name);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): void
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            $context->clear();
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isShielded(ServerRequestInterface $request): bool
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            if ($context->isShielded($request)) {
                $this->activeContext = $context;

                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles(ServerRequestInterface $request): array
    {
        $this->activeContext = null;

        /** @var ContextInterface $context */
        foreach ($this->contexts as $context) {
            $roles = $context->getRoles($request);
            if (!empty($roles)) {
                $this->activeContext = $context;

                return $roles;
            }
        }

        return [];
    }
}
