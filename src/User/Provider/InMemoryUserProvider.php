<?php

namespace Bitty\Security\User\Provider;

use Bitty\Security\User\Provider\AbstractUserProvider;
use Bitty\Security\User\User;
use Bitty\Security\User\UserInterface;

class InMemoryUserProvider extends AbstractUserProvider
{
    /**
     * @var array Array of string[]
     */
    private $users = [];

    /**
     * Users array should be structured like:
     *
     * [
     *     'bob' => [
     *         'password' => 'some_encoded_password',
     *         'salt' => string|null,
     *         'roles' => string[],
     *     ],
     *     'frank' => [
     *         'password' => 'some_encoded_password',
     *         'salt' => string|null,
     *         'roles' => string[],
     *     ],
     * ]
     *
     * @param array $users Array of string[]
     */
    public function __construct(array $users)
    {
        $this->users = $users;
    }

    /**
     * {@inheritDoc}
     */
    public function getUser(string $username): ?UserInterface
    {
        $this->checkUsername($username);

        if (!isset($this->users[$username])) {
            return null;
        }

        $user = $this->users[$username];
        if (empty($user['password'])) {
            return null;
        }

        $password = $user['password'];
        $salt     = empty($user['salt']) ? null : $user['salt'];
        $roles    = empty($user['roles']) ? [] : (array) $user['roles'];

        return new User($username, $password, $salt, $roles);
    }
}
