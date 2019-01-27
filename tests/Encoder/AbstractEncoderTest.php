<?php

namespace Bitty\Tests\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;
use Bitty\Security\Encoder\EncoderInterface;
use Bitty\Security\Exception\AuthenticationException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AbstractEncoderTest extends TestCase
{
    /**
     * @var AbstractEncoder|MockObject
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = $this->getMockForAbstractClass(AbstractEncoder::class);
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(EncoderInterface::class, $this->fixture);
    }

    public function testVerifyBlocksLongPasswords(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid password.');

        $this->fixture->verify(uniqid(), $password);
    }

    public function testVerifyCallsEncode(): void
    {
        $password = uniqid();
        $salt     = uniqid();

        $this->fixture->expects(self::once())
            ->method('encode')
            ->with($password, $salt);

        $this->fixture->verify(uniqid(), $password, $salt);
    }

    public function testVerifyHasMatch(): void
    {
        $encoded = uniqid();

        $this->fixture->method('encode')->willReturn($encoded);

        $actual = $this->fixture->verify($encoded, uniqid());

        self::assertTrue($actual);
    }

    public function testVerifyHasNoMatch(): void
    {
        $this->fixture->method('encode')->willReturn(uniqid());

        $actual = $this->fixture->verify(uniqid(), uniqid());

        self::assertFalse($actual);
    }
}
