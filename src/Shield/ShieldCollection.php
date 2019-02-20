<?php

namespace Bitty\Security\Shield;

use Bitty\Container\ContainerAwareInterface;
use Bitty\Security\Context\ContextCollection;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Shield\ShieldInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ShieldCollection implements ShieldInterface, ContainerAwareInterface
{
    /**
     * @var ContainerInterface|null
     */
    private $container = null;

    /**
     * @var ShieldInterface[]
     */
    private $shields = [];

    /**
     * @var ContextCollection
     */
    private $context = null;

    /**
     * @param ShieldInterface[] $shields
     */
    public function __construct(array $shields = [])
    {
        $this->context = new ContextCollection();

        foreach ($shields as $shield) {
            $this->add($shield);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function setContainer(?ContainerInterface $container = null): void
    {
        foreach ($this->shields as $shield) {
            if (!($shield instanceof ContainerAwareInterface)) {
                continue;
            }

            $shield->setContainer($container);
        }

        $this->container = $container;
    }

    /**
     * {@inheritDoc}
     */
    public function getContainer(): ?ContainerInterface
    {
        return $this->container;
    }

    /**
     * Adds a shield to the collection.
     *
     * @param ShieldInterface $shield
     */
    public function add(ShieldInterface $shield): void
    {
        if ($shield instanceof ContainerAwareInterface) {
            $shield->setContainer($this->container);
        }

        $this->shields[] = $shield;
        $this->context->add($shield->getContext());
    }

    /**
     * {@inheritDoc}
     */
    public function handle(ServerRequestInterface $request): ?ResponseInterface
    {
        foreach ($this->shields as $shield) {
            $response = $shield->handle($request);
            if ($response) {
                return $response;
            }
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function getContext(): ContextInterface
    {
        return $this->context;
    }
}
