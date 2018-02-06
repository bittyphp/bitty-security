<?php

namespace Bitty\Security\User\Provider;

use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\User\Provider\UserProviderInterface;

abstract class AbstractUserProvider implements UserProviderInterface
{
    /**
     * {@inheritDoc}
     */
    abstract public function getUser($username);

    /**
     * Checks for usernames that are too long.
     *
     * @param string $username
     *
     * @throws AuthenticationException
     */
    protected function checkUsername($username)
    {
        if (strlen($username) > UserProviderInterface::MAX_USERNAME_LEN) {
            throw new AuthenticationException('Invalid username.');
        }
    }
}
