<?php

namespace Bitty\Tests\Security\Encoder;

use Bitty\Security\Encoder\AbstractEncoder;
use Bitty\Security\Encoder\MessageDigestEncoder;
use Bitty\Security\Exception\AuthenticationException;
use PHPUnit\Framework\TestCase;

class MessageDigestEncoderTest extends TestCase
{
    /**
     * @var MessageDigestEncoder
     */
    private $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new MessageDigestEncoder('md5');
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AbstractEncoder::class, $this->fixture);
    }

    /**
     * @param string $algorithm
     * @param string|null $salt
     * @param string $expected
     *
     * @dataProvider samplePasswords
     */
    public function testEncode(string $algorithm, ?string $salt, string $expected): void
    {
        $this->fixture = new MessageDigestEncoder($algorithm);

        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN);

        $actual = $this->fixture->encode($password, $salt);

        self::assertEquals($expected, $actual);
    }

    public function samplePasswords(): array
    {
        return [
            'md5, no salt' => [
                'algorithm' => 'md5',
                'salt' => null,
                'expected' => '793e21e2f9447906af9c7ad6ec964128',
            ],
            'md5, with salt' => [
                'algorithm' => 'md5',
                'salt' => 'saltydog',
                'expected' => '18ec7d42f277953a4fb795945823a19d',
            ],
            'sha1, no salt' => [
                'algorithm' => 'sha1',
                'salt' => null,
                'expected' => 'a7524c1bb82a686d42e068329c5d47a5ace1aabd',
            ],
            'sha1, with salt' => [
                'algorithm' => 'sha1',
                'salt' => 'saltydog',
                'expected' => 'afebb1768c691c86f3779f2ca671004498bfcf19',
            ],
            'sha256, no salt' => [
                'algorithm' => 'sha256',
                'salt' => null,
                'expected' => '86f88b283dd6aa52d173fcbed559fda6cafc29b4b631597ca1ab0580764b162a',
            ],
            'sha256, with salt' => [
                'algorithm' => 'sha256',
                'salt' => 'saltydog',
                'expected' => 'd1186e5056a6e76ac6a697cacb613317322ff3b101725a2b63a216128458b384',
            ],
        ];
    }

    public function testEncodeBlocksLongPasswords(): void
    {
        $password = str_repeat('*', AbstractEncoder::MAX_PASSWORD_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid password.');

        $this->fixture->encode($password);
    }

    public function testInvalidAlgorithm(): void
    {
        $algorithm = uniqid();

        self::expectException(\InvalidArgumentException::class);
        self::expectExceptionMessage('"'.$algorithm.'" is not a valid hash algorithm.');

        new MessageDigestEncoder($algorithm);
    }
}
