<?php

namespace Bitty\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;

class PlainTextEncoder extends AbstractEncoder
{
    /**
     * {@inheritDoc}
     */
    public function encode(string $password, ?string $salt = null): string
    {
        $this->checkPassword($password);

        return $password;
    }
}
