<?php

namespace Bitty\Tests\Security\Context;

use Bitty\Http\Session\SessionInterface;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Context\SessionContext;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class SessionContextTest extends TestCase
{
    /**
     * @var SessionContext
     */
    protected $fixture = null;

    /**
     * @var string
     */
    protected $name = null;

    /**
     * @var SessionInterface|MockObject
     */
    protected $session = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->name    = uniqid();
        $this->session = $this->createMock(SessionInterface::class);

        $this->fixture = new SessionContext($this->session, $this->name, []);
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
        $this->fixture = new SessionContext($this->session, uniqid(), [], $options);

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

    public function testSetCallsIsStarted(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(true);
        $this->session->expects(self::never())->method('start');

        $this->fixture->set(uniqid(), uniqid());
    }

    public function testSetStartsSession(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(false);
        $this->session->expects(self::once())->method('start');

        $this->fixture->set(uniqid(), uniqid());
    }

    public function testSet(): void
    {
        $name  = uniqid();
        $value = uniqid();

        $this->session->expects(self::once())
            ->method('set')
            ->with($this->name.'/'.$name, $value);

        $this->fixture->set($name, $value);
    }

    public function testSetUser(): void
    {
        $now   = time();
        $value = uniqid();

        $expectedData = [
            ['isStarted', []],
            ['set', [$this->name.'/destroy', $now + 30]],
            ['regenerate', [false]],
            ['remove', [$this->name.'/destroy']],
            ['set', [$this->name.'/login', $now]],
            ['set', [$this->name.'/active', $now]],
            ['set', [$this->name.'/expires', $now + 86400]],
            ['set', [$this->name.'/user', $value]],
        ];

        $spy = self::any();
        $this->session->method('isStarted')->willReturn(true);
        $this->session->expects($spy)->method(self::anything());

        $this->fixture->set('user', $value);

        $invocations = $spy->getInvocations();
        self::assertCount(count($expectedData), $invocations);

        foreach ($invocations as $invocation) {
            $method = $invocation->getMethodName();
            $params = $invocation->getParameters();

            $expected = array_shift($expectedData);
            if (empty($expected)) {
                self::fail('No expected data');
            }

            self::assertEquals($expected[0], $method);
            if ($method === 'set') {
                self::assertEquals(array_shift($expected[1]), $params[0]);
                self::assertEquals(array_shift($expected[1]), $params[1], '', 1.0);
            } else {
                self::assertEquals($expected[1], $params);
            }
        }
    }

    public function testGetCallsIsStarted(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(true);
        $this->session->expects(self::never())->method('start');

        $this->fixture->get(uniqid(), uniqid());
    }

    public function testGetStartsSession(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(false);
        $this->session->expects(self::once())->method('start');

        $this->fixture->get(uniqid(), uniqid());
    }

    public function testGet(): void
    {
        $name    = uniqid();
        $default = uniqid();
        $value   = uniqid();

        $this->session->expects(self::once())
            ->method('get')
            ->with($this->name.'/'.$name, $default)
            ->willReturn($value);

        $actual = $this->fixture->get($name, $default);

        self::assertEquals($value, $actual);
    }

    /**
     * @param string $name
     * @param string $default
     * @param string[] $data
     * @param array[] $map
     * @param array[] $expectedData
     *
     * @dataProvider sampleGetUserExpired
     */
    public function testGetUser(
        string $name,
        string $default,
        array $data,
        array $map,
        array $expectedData
    ): void {
        $this->fixture = new SessionContext($this->session, $name, [], ['timeout' => -1]);

        $this->session->method('all')->willReturn($data);
        $this->session->method('get')->willReturnMap($map);
        $this->session->method('isStarted')->willReturn(true);

        $spy = self::any();
        $this->session->expects($spy)->method(self::anything());

        $this->fixture->get('user', $default);

        $invocations = $spy->getInvocations();
        self::assertCount(count($expectedData), $invocations);

        foreach ($invocations as $invocation) {
            $method = $invocation->getMethodName();
            $params = $invocation->getParameters();

            $expected = array_shift($expectedData);

            self::assertEquals($expected[0], $method);
            if ($method === 'set') {
                self::assertEquals($expected[1][0], $params[0]);
                self::assertEquals($expected[1][1], $params[1], '', 1.0);
            } else {
                self::assertEquals($expected[1], $params);
            }
        }
    }

    public function sampleGetUserExpired(): array
    {
        $now     = time();
        $name    = uniqid();
        $default = uniqid();
        $keyA    = uniqid();
        $keyB    = uniqid();
        $data    = [
            uniqid().'/'.uniqid() => uniqid(),
            $name.'/'.$keyA => uniqid(),
            uniqid().'/'.uniqid() => uniqid(),
            $name.'/'.$keyB => uniqid(),
            uniqid().'/'.uniqid() => uniqid(),
        ];
        $clear   = [
            ['isStarted', []],
            ['get', [$name.'/expires', 0]],
            ['get', [$name.'/destroy', INF]],
            ['get', [$name.'/active', 0]],
            ['all', []],
            ['remove', [$name.'/'.$keyA]],
            ['remove', [$name.'/'.$keyB]],
            ['get', [$name.'/user', $default]],
        ];

        return [
            'not expired, destroyed, or inactive' => [
                'name' => $name,
                'default' => $default,
                'data' => $data,
                'map' => [
                    [$name.'/expires', 0, INF],
                    [$name.'/destroy', INF, INF],
                    [$name.'/active', 0, INF],
                ],
                'expected' => [
                    ['isStarted', []],
                    ['get', [$name.'/expires', 0]],
                    ['get', [$name.'/destroy', INF]],
                    ['get', [$name.'/active', 0]],
                    ['set', [$name.'/active', $now]],
                    ['get', [$name.'/user', $default]],
                ],
            ],
            'is expired' => [
                'name' => $name,
                'default' => $default,
                'data' => $data,
                'map' => [
                    [$name.'/expires', 0, $now - 1],
                    [$name.'/destroy', INF, INF],
                    [$name.'/active', 0, INF],
                ],
                'expected' => $clear,
            ],
            'is destroyed' => [
                'name' => $name,
                'default' => $default,
                'data' => $data,
                'map' => [
                    [$name.'/expires', 0, INF],
                    [$name.'/destroy', INF, $now - 1],
                    [$name.'/active', 0, INF],
                ],
                'expected' => $clear,
            ],
            'is inactive' => [
                'name' => $name,
                'default' => $default,
                'data' => $data,
                'map' => [
                    [$name.'/expires', 0, INF],
                    [$name.'/destroy', INF, INF],
                    [$name.'/active', 0, $now],
                ],
                'expected' => $clear,
            ],
        ];
    }

    public function testGetUserReturnsSessionResponse(): void
    {
        $default = uniqid();
        $value   = uniqid();

        $this->session->method('get')->willReturnMap(
            [
                [$this->name.'/user', $default, $value],
            ]
        );

        $actual = $this->fixture->get('user', $default);

        self::assertEquals($value, $actual);
    }

    public function testRemoveCallsIsStarted(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(true);
        $this->session->expects(self::never())->method('start');

        $this->fixture->remove(uniqid());
    }

    public function testRemoveStartsSession(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(false);
        $this->session->expects(self::once())->method('start');

        $this->fixture->remove(uniqid());
    }

    public function testRemove(): void
    {
        $name = uniqid();

        $this->session->expects(self::once())
            ->method('remove')
            ->with($this->name.'/'.$name);

        $this->fixture->remove($name);
    }

    public function testClearCallsIsStarted(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(true);
        $this->session->expects(self::never())->method('start');

        $this->fixture->clear();
    }

    public function testClearStartsSession(): void
    {
        $this->session->expects(self::once())->method('isStarted')->willReturn(false);
        $this->session->expects(self::once())->method('start');

        $this->fixture->clear();
    }

    public function testClear(): void
    {
        $keyA = uniqid();
        $keyB = uniqid();
        $data = [
            uniqid().'/'.uniqid() => uniqid(),
            $this->name.'/'.$keyA => uniqid(),
            uniqid().'/'.uniqid() => uniqid(),
            $this->name.'/'.$keyB => uniqid(),
            uniqid().'/'.uniqid() => uniqid(),
        ];

        $this->session->expects(self::once())
            ->method('all')
            ->willReturn($data);

        $this->session->expects(self::exactly(2))
            ->method('remove')
            ->withConsecutive(
                [$this->name.'/'.$keyA],
                [$this->name.'/'.$keyB]
            );

        $this->fixture->clear();
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

        $this->fixture = new SessionContext($this->session, uniqid(), $paths);

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

        $this->fixture = new SessionContext($this->session, $name, $paths);

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
