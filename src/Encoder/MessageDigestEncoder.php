<?php

namespace Bitty\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;

class MessageDigestEncoder extends AbstractEncoder
{
    /**
     * @var string
     */
    protected $algorithm = null;

    /**
     * @param string $algorithm
     */
    public function __construct(string $algorithm)
    {
        if (!in_array($algorithm, hash_algos(), true)) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not a valid hash algorithm.', $algorithm)
            );
        }

        $this->algorithm = $algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function encode(string $password, string $salt = null): string
    {
        $this->checkPassword($password);

        if ($salt) {
            $password = $salt.':'.$password;
        }

        return hash($this->algorithm, $password);
    }
}
