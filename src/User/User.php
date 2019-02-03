<?php

namespace Bitty\Security\User;

use Bitty\Security\User\UserInterface;

class User implements UserInterface
{
    /**
     * @var string
     */
    private $username = null;

    /**
     * @var string
     */
    private $password = null;

    /**
     * @var string|null
     */
    private $salt = null;

    /**
     * @var string[]
     */
    private $roles = null;

    /**
     * @param string $username
     * @param string $password The password in encoded form.
     * @param string|null $salt
     * @param string[] $roles
     */
    public function __construct(
        string $username,
        string $password,
        string $salt = null,
        array $roles = []
    ) {
        $this->username = $username;
        $this->password = $password;
        $this->salt     = $salt;
        $this->roles    = $roles;
    }

    /**
     * @return string[]
     */
    public function __sleep(): array
    {
        return ['username', 'password', 'salt', 'roles'];
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * {@inheritDoc}
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * {@inheritDoc}
     */
    public function getSalt(): ?string
    {
        return $this->salt;
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles(): array
    {
        return $this->roles;
    }
}
