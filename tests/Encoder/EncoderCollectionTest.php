<?php

namespace Bitty\Tests\Security\Encoder;

use Bitty\Security\Encoder\EncoderCollection;
use Bitty\Security\Encoder\EncoderCollectionInterface;
use Bitty\Security\Encoder\EncoderInterface;
use Bitty\Security\Exception\SecurityException;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\TestCase;

class EncoderCollectionTest extends TestCase
{
    /**
     * @var EncoderCollection
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new EncoderCollection();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(EncoderCollectionInterface::class, $this->fixture);
    }

    public function testAddEncoderThrowsException(): void
    {
        $encoder = $this->createEncoder();
        $class   = uniqid();

        self::expectException(SecurityException::class);
        self::expectExceptionMessage('User class '.$class.' does not exist.');

        $this->fixture->addEncoder($encoder, $class);
    }

    public function testGetEncoder(): void
    {
        $user     = $this->createUser();
        $encoderA = $this->createEncoder();
        $encoderB = $this->createEncoder();
        $classA   = \stdClass::class;
        $classB   = UserInterface::class;

        $this->fixture->addEncoder($encoderA, $classA);
        $this->fixture->addEncoder($encoderB, $classB);

        $actual = $this->fixture->getEncoder($user);

        self::assertNotSame($encoderA, $actual);
        self::assertSame($encoderB, $actual);
    }

    public function testGetEncoderNoMatchingEncoders(): void
    {
        $user    = $this->createUser();
        $encoder = $this->createEncoder();

        $this->fixture->addEncoder($encoder, \stdClass::class);

        self::expectException(SecurityException::class);
        self::expectExceptionMessage('Unable to determine encoder for '.get_class($user).'.');

        $this->fixture->getEncoder($user);
    }

    public function testGetEncoderNoEncoders(): void
    {
        $user = $this->createUser();

        self::expectException(SecurityException::class);
        self::expectExceptionMessage('Unable to determine encoder for '.get_class($user).'.');

        $this->fixture->getEncoder($user);
    }

    /**
     * @return EncoderInterface
     */
    protected function createEncoder(): EncoderInterface
    {
        return $this->createMock(EncoderInterface::class);
    }

    /**
     * @return UserInterface
     */
    protected function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }
}
