<?php

namespace Bitty\Security\User\Provider;

use Bitty\Security\User\Provider\UserProviderInterface;
use Bitty\Security\User\UserInterface;

class UserProviderCollection implements UserProviderInterface
{
    /**
     * @var UserProviderInterface[]
     */
    private $providers = [];

    /**
     * @param UserProviderInterface[] $providers
     */
    public function __construct(array $providers = [])
    {
        foreach ($providers as $provider) {
            $this->add($provider);
        }
    }

    /**
     * Adds a user provider to the collection.
     *
     * @param UserProviderInterface $userProvider
     */
    public function add(UserProviderInterface $userProvider): void
    {
        $this->providers[] = $userProvider;
    }

    /**
     * {@inheritDoc}
     */
    public function getUser(string $username): ?UserInterface
    {
        foreach ($this->providers as $provider) {
            $user = $provider->getUser($username);
            if ($user) {
                return $user;
            }
        }

        return null;
    }
}
