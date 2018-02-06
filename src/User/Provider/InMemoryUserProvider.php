<?php

namespace Bitty\Security\User\Provider;

use Bitty\Security\User\Provider\AbstractUserProvider;
use Bitty\Security\User\User;

class InMemoryUserProvider extends AbstractUserProvider
{
    /**
     * @var string[]
     */
    protected $users = [];

    /**
     * @param string[] $users
     */
    public function __construct(array $users)
    {
        $this->users = $users;
    }

    /**
     * {@inheritDoc}
     */
    public function getUser($username)
    {
        $this->checkUsername($username);

        if (!isset($this->users[$username])) {
            return;
        }

        $user = $this->users[$username];
        if (empty($user['password'])) {
            return;
        }

        $password = $user['password'];
        $salt     = empty($user['salt']) ? null : $user['salt'];
        $roles    = empty($user['roles']) ? [] : (array) $user['roles'];

        return new User($username, $password, $salt, $roles);
    }
}
