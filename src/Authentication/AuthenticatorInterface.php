<?php

namespace Bitty\Security\Authentication;

use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\User\UserInterface;

interface AuthenticatorInterface
{
    /**
     * Authenticates a user.
     *
     * @param string $username
     * @param string $password
     *
     * @return UserInterface
     *
     * @throws AuthenticationException
     */
    public function authenticate(string $username, string $password): UserInterface;

    /**
     * Reloads a user.
     *
     * This ensures the user is still valid and loads any permission changes
     * that might have occurred.
     *
     * @param UserInterface $user
     *
     * @return UserInterface|null
     */
    public function reloadUser(UserInterface $user): ?UserInterface;
}
