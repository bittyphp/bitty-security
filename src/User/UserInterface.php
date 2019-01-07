<?php

namespace Bitty\Security\User;

interface UserInterface
{
    /**
     * Gets the username.
     *
     * @return string
     */
    public function getUsername(): string;

    /**
     * Gets the encoded password.
     *
     * @return string
     */
    public function getPassword(): string;

    /**
     * Gets the password salt.
     *
     * @return string|null
     */
    public function getSalt(): ?string;

    /**
     * Gets the roles the user has.
     *
     * @return string[]
     */
    public function getRoles(): array;
}
