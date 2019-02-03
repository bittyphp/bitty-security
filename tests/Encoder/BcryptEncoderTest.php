<?php

namespace Bitty\Tests\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;
use Bitty\Security\Encoder\BcryptEncoder;
use Bitty\Security\Exception\AuthenticationException;
use PHPUnit\Framework\TestCase;

class BcryptEncoderTest extends TestCase
{
    /**
     * @var BcryptEncoder
     */
    private $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new BcryptEncoder();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AbstractEncoder::class, $this->fixture);
    }

    public function testEncode(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN);

        $actualA = $this->fixture->encode($password);
        $actualB = $this->fixture->encode($password);

        self::assertStringStartsWith('$2y$10$', $actualA);
        self::assertStringStartsWith('$2y$10$', $actualB);
        self::assertEquals(60, strlen($actualA));
        self::assertEquals(60, strlen($actualB));
        self::assertNotEquals($actualA, $actualB);
    }

    public function testEncodeWithCost(): void
    {
        $cost = rand(4, 9);

        $this->fixture = new BcryptEncoder($cost);

        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN);

        $actualA = $this->fixture->encode($password);
        $actualB = $this->fixture->encode($password);

        self::assertStringStartsWith('$2y$0'.$cost.'$', $actualA);
        self::assertStringStartsWith('$2y$0'.$cost.'$', $actualB);
        self::assertEquals(60, strlen($actualA));
        self::assertEquals(60, strlen($actualB));
        self::assertNotEquals($actualA, $actualB);
    }

    public function testEncodeFails(): void
    {
        $level = error_reporting();
        error_reporting(0);

        $this->fixture = new BcryptEncoder(3);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Failed to encode password.');

        $this->fixture->encode(uniqid());

        error_reporting($level);
    }

    public function testEncodeBlocksLongPasswords(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid password.');

        $this->fixture->encode($password);
    }

    public function testVerifyBlocksLongPasswords(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid password.');

        $this->fixture->verify(uniqid(), $password);
    }

    public function testVerifyHasMatch(): void
    {
        $password = uniqid();
        $encoded  = $this->fixture->encode($password);

        $actual = $this->fixture->verify($encoded, $password);

        self::assertTrue($actual);
    }

    public function testVerifyHasNoMatch(): void
    {
        $password = uniqid();
        $encoded  = $this->fixture->encode($password);

        $actual = $this->fixture->verify($encoded, uniqid());

        self::assertFalse($actual);
    }
}
