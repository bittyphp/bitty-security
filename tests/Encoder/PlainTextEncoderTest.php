<?php

namespace Bitty\Tests\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;
use Bitty\Security\Encoder\PlainTextEncoder;
use Bitty\Security\Exception\AuthenticationException;
use PHPUnit\Framework\TestCase;

class PlainTextEncoderTest extends TestCase
{
    /**
     * @var PlainTextEncoder
     */
    private $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new PlainTextEncoder();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AbstractEncoder::class, $this->fixture);
    }

    public function testEncode(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN);

        $actual = $this->fixture->encode($password);

        self::assertEquals($password, $actual);
    }

    public function testEncodeBlocksLongPasswords(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid password.');

        $this->fixture->encode($password);
    }
}
