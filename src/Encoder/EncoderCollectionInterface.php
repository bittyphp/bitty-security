<?php

namespace Bitty\Security\Encoder;

use Bitty\Security\Encoder\EncoderInterface;
use Bitty\Security\Exception\SecurityException;
use Bitty\Security\User\UserInterface;

interface EncoderCollectionInterface
{
    /**
     * Gets the password encoder for the given user.
     *
     * @param UserInterface $user
     *
     * @return EncoderInterface
     *
     * @throws SecurityException
     */
    public function getEncoder(UserInterface $user): EncoderInterface;
}
