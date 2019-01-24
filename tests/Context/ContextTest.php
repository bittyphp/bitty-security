<?php

namespace Bitty\Tests\Security\Context;

use Bitty\Security\Context\Context;
use Bitty\Security\Context\ContextInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class ContextTest extends TestCase
{
    /**
     * @var Context
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new Context(uniqid(), []);
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ContextInterface::class, $this->fixture);
    }

    /**
     * @param mixed[] $options
     * @param bool $expected
     *
     * @dataProvider sampleIsDefault
     */
    public function testIsDefault(array $options, bool $expected): void
    {
        $this->fixture = new Context(uniqid(), [], $options);

        $actual = $this->fixture->isDefault();

        self::assertEquals($expected, $actual);
    }

    public function sampleIsDefault(): array
    {
        return [
            'no options' => [
                'options' => [],
                'expected' => true,
            ],
            'default true' => [
                'options' => ['default' => true],
                'expected' => true,
            ],
            'default false' => [
                'options' => ['default' => false],
                'expected' => false,
            ],
            'default truthy' => [
                'options' => ['default' => rand(1, 9999)],
                'expected' => true,
            ],
            'default falsy' => [
                'options' => ['default' => 0],
                'expected' => false,
            ],
            'default null' => [
                'options' => ['default' => null],
                'expected' => false,
            ],
            'default string' => [
                'options' => ['default' => uniqid()],
                'expected' => true,
            ],
            'default object' => [
                'options' => ['default' => (object) []],
                'expected' => true,
            ],
        ];
    }

    public function testSet(): void
    {
        $name  = uniqid();
        $value = uniqid();

        $this->fixture->set($name, $value);

        $actual = $this->fixture->get($name);

        self::assertEquals($value, $actual);
    }

    public function testSetUser(): void
    {
        $level = error_reporting();
        error_reporting(0);

        $ttl   = rand();
        $now   = time();
        $value = uniqid();

        $this->fixture = new Context(uniqid(), [], ['ttl' => $ttl]);

        $this->fixture->set('user', $value);

        self::assertEquals($now, $this->fixture->get('login'), '', 1.0);
        self::assertEquals($now, $this->fixture->get('active'), '', 1.0);
        self::assertEquals($now + $ttl, $this->fixture->get('expires'), '', 1.0);

        error_reporting($level);
    }

    public function testGetUserClearsDataWhenInactive(): void
    {
        $level = error_reporting();
        error_reporting(0);

        $name    = uniqid();
        $default = uniqid();

        $this->fixture = new Context(uniqid(), [], ['timeout' => -1]);

        $this->fixture->set('user', uniqid());
        $this->fixture->set($name, uniqid());

        $actual = $this->fixture->get('user', $default);

        self::assertEquals($default, $actual);

        error_reporting($level);
    }

    public function testGetUserClearsDataWhenExpired(): void
    {
        $level = error_reporting();
        error_reporting(0);

        $name    = uniqid();
        $default = uniqid();

        $this->fixture = new Context(uniqid(), [], ['ttl' => -1]);

        $this->fixture->set('user', uniqid());
        $this->fixture->set($name, uniqid());

        $actual = $this->fixture->get('user', $default);

        self::assertEquals($default, $actual);

        error_reporting($level);
    }

    public function testGetUserUpdatesActiveTime(): void
    {
        $now = time();

        $this->fixture->set('expires', $now + rand(100, 999));
        $this->fixture->set('active', $now - 86399);
        $this->fixture->get('user', uniqid());

        $actual = $this->fixture->get('active');

        self::assertEquals($now, $actual, '', 1.0);
    }

    public function testGetUnsetValue(): void
    {
        $default = uniqid();

        $actual = $this->fixture->get(uniqid(), $default);

        self::assertEquals($default, $actual);
    }

    public function testRemove(): void
    {
        $name = uniqid();

        $this->fixture->set($name, uniqid());

        try {
            $this->fixture->remove($name);
        } catch (\Exception $e) {
            self::fail();
        }

        self::assertTrue(true);
    }

    public function testRemoveUnsetValue(): void
    {
        try {
            $this->fixture->remove(uniqid());
        } catch (\Exception $e) {
            self::fail();
        }

        self::assertTrue(true);
    }

    public function testClear(): void
    {
        $name    = uniqid();
        $default = uniqid();

        $this->fixture->set(uniqid(), uniqid());
        $this->fixture->set(uniqid(), uniqid());
        $this->fixture->set($name, uniqid());
        $this->fixture->set(uniqid(), uniqid());
        $this->fixture->set(uniqid(), uniqid());

        $this->fixture->clear();

        $actual = $this->fixture->get($name, $default);

        self::assertEquals($default, $actual);
    }

    /**
     * @param array $paths
     * @param string $path
     * @param bool $expected
     *
     * @dataProvider sampleIsShielded
     */
    public function testIsShielded(array $paths, string $path, bool $expected): void
    {
        $request = $this->createRequest($path);

        $this->fixture = new Context(uniqid(), $paths);

        $actual = $this->fixture->isShielded($request);

        self::assertEquals($expected, $actual);
    }

    public function sampleIsShielded(): array
    {
        return [
            'no paths' => [
                'paths' => [],
                'path' => uniqid('/'),
                'expected' => false,
            ],
            'no matching path' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                ],
                'path' => uniqid('/'),
                'expected' => false,
            ],
            'matching path, with roles' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                    '^/' => [uniqid()],
                    uniqid('b') => [uniqid()],
                ],
                'path' => uniqid('/'),
                'expected' => true,
            ],
            'matching path, no roles' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                    '^/' => [],
                    uniqid('b') => [uniqid()],
                ],
                'path' => uniqid('/'),
                'expected' => false,
            ],
        ];
    }

    /**
     * @param array[] $paths
     * @param string $name
     * @param string $path
     * @param mixed[] $expected
     *
     * @dataProvider sampleGetPatternMatch
     */
    public function testGetPatternMatch(array $paths, string $name, string $path, array $expected): void
    {
        $request = $this->createRequest($path);

        $this->fixture = new Context($name, $paths);

        $actual = $this->fixture->getPatternMatch($request);

        self::assertEquals($expected, $actual);
    }

    public function sampleGetPatternMatch(): array
    {
        $name  = uniqid();
        $roles = [uniqid(), uniqid()];

        return [
            'no paths' => [
                'paths' => [],
                'name' => uniqid(),
                'path' => uniqid('/'),
                'expected' => [],
            ],
            'non-matching path' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                    uniqid('b') => [uniqid()],
                ],
                'name' => uniqid(),
                'path' => uniqid('/'),
                'expected' => [],
            ],
            'matching path' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                    '^/' => $roles,
                    uniqid('b') => [uniqid()],
                ],
                'name' => $name,
                'path' => uniqid('/'),
                'expected' => [
                    'shield' => $name,
                    'pattern' => '^/',
                    'roles' => $roles,
                ],
            ],
            'overlapping paths' => [
                'paths' => [
                    uniqid('a') => [uniqid()],
                    '^/foo' => $roles,
                    '^/' => [uniqid()],
                    uniqid('b') => [uniqid()],
                ],
                'name' => $name,
                'path' => uniqid('/foo'),
                'expected' => [
                    'shield' => $name,
                    'pattern' => '^/foo',
                    'roles' => $roles,
                ],
            ],
        ];
    }

    /**
     * @param string $path
     *
     * @return ServerRequestInterface
     */
    protected function createRequest(string $path): ServerRequestInterface
    {
        $uri = $this->createConfiguredMock(
            UriInterface::class,
            ['getPath' => $path]
        );

        return $this->createConfiguredMock(
            ServerRequestInterface::class,
            ['getUri' => $uri]
        );
    }
}
