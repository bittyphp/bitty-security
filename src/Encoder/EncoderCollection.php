<?php

namespace Bitty\Security\Encoder;

use Bitty\Security\Encoder\EncoderCollectionInterface;
use Bitty\Security\Encoder\EncoderInterface;
use Bitty\Security\Exception\SecurityException;
use Bitty\Security\User\UserInterface;

class EncoderCollection implements EncoderCollectionInterface
{
    /**
     * @var EncoderInterface[]
     */
    protected $encoders = [];

    /**
     * @param EncoderInterface[]|EncoderInterface $encoders
     */
    public function __construct($encoders)
    {
        if (is_array($encoders)) {
            foreach ($encoders as $class => $encoder) {
                $this->addEncoder($encoder, $class);
            }
        } else {
            $this->addEncoder($encoders, UserInterface::class);
        }
    }

    /**
     * Adds an encoder for the given user class.
     *
     * @param EncoderInterface $encoder
     * @param string $userClass
     *
     * @throws SecurityException
     */
    public function addEncoder(EncoderInterface $encoder, string $userClass): void
    {
        if (!class_exists($userClass) && !interface_exists($userClass)) {
            throw new SecurityException(
                sprintf('User class %s does not exist.', $userClass)
            );
        }

        $this->encoders[$userClass] = $encoder;
    }

    /**
     * {@inheritDoc}
     */
    public function getEncoder(UserInterface $user): EncoderInterface
    {
        foreach ($this->encoders as $class => $encoder) {
            if ($user instanceof $class) {
                return $encoder;
            }
        }

        throw new SecurityException(
            sprintf('Unable to determine encoder for %s.', get_class($user))
        );
    }
}
