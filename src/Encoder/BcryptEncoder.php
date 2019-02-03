<?php

namespace Bitty\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;
use Bitty\Security\Exception\AuthenticationException;

class BcryptEncoder extends AbstractEncoder
{
    /**
     * @var int
     */
    private $cost = null;

    /**
     * @param int $cost
     */
    public function __construct(int $cost = 10)
    {
        $this->cost = $cost;
    }

    /**
     * {@inheritDoc}
     */
    public function encode(string $password, string $salt = null): string
    {
        $this->checkPassword($password);

        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->cost]);
        if (!$hash) {
            throw new AuthenticationException('Failed to encode password.');
        }

        return $hash;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $encoded, string $password, string $salt = null): bool
    {
        $this->checkPassword($password);

        return password_verify($password, $encoded);
    }
}
