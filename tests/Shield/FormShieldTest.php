<?php

namespace Bitty\Tests\Security\Shield;

use Bitty\EventManager\EventManagerInterface;
use Bitty\Http\RedirectResponse;
use Bitty\Security\Authentication\AuthenticatorInterface;
use Bitty\Security\Authorization\AuthorizerInterface;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\Exception\AuthorizationException;
use Bitty\Security\Shield\AbstractShield;
use Bitty\Security\Shield\FormShield;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class FormShieldTest extends TestCase
{
    /**
     * @var FormShield
     */
    protected $fixture = null;

    /**
     * @var ContextInterface|MockObject
     */
    protected $context = null;

    /**
     * @var AuthenticatorInterface|MockObject
     */
    protected $authenticator = null;

    /**
     * @var AuthorizerInterface|MockObject
     */
    protected $authorizer = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context       = $this->createMock(ContextInterface::class);
        $this->authenticator = $this->createMock(AuthenticatorInterface::class);
        $this->authorizer    = $this->createMock(AuthorizerInterface::class);

        $this->setUpFixture();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AbstractShield::class, $this->fixture);
    }

    public function testHandleCallsContextGetRoles(): void
    {
        $request = $this->createRequest();

        $this->context->expects(self::once())
            ->method('getRoles')
            ->with($request);

        $this->fixture->handle($request);
    }

    public function testHandleCallsContextGetUser(): void
    {
        $request = $this->createRequest();

        $this->context->method('getRoles')->willReturn([uniqid()]);

        $this->context->expects(self::once())
            ->method('get')
            ->with('user');

        $this->fixture->handle($request);
    }

    public function testHandleCallsAuthenticatorReloadUser(): void
    {
        $request = $this->createRequest();
        $user    = $this->createUser();

        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($user);

        $this->authenticator->expects(self::once())
            ->method('reloadUser')
            ->with($user);

        $this->fixture->handle($request);
    }

    public function testHandleReloadedUserCallsAuthorizerAuthorize(): void
    {
        $request = $this->createRequest();
        $user    = $this->createUser();
        $roles   = [uniqid()];

        $this->context->method('getRoles')->willReturn($roles);
        $this->context->method('get')->with('user')->willReturn($this->createUser());
        $this->authenticator->method('reloadUser')->willReturn($user);

        $this->authorizer->expects(self::once())
            ->method('authorize')
            ->with($user, $roles);

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function testHandleCallsEventManagerOnAuthorize(): void
    {
        $request      = $this->createRequest();
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);
        $user         = $this->createUser();

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($this->createUser());
        $this->authenticator->method('reloadUser')->willReturn($user);

        $eventManager->expects(self::exactly(2))
            ->method('trigger')
            ->withConsecutive(
                ['security.authorization.start', $user, []],
                ['security.authorization.success', $user, []]
            );

        $this->fixture->handle($request);
    }

    public function testHandleAuthorizerThrowsException(): void
    {
        $request      = $this->createRequest();
        $user         = $this->createUser();
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($this->createUser());
        $this->authenticator->method('reloadUser')->willReturn($user);

        $message   = uniqid();
        $exception = new AuthorizationException($message);
        self::expectException(AuthorizationException::class);
        self::expectExceptionMessage($message);

        $this->authorizer->method('authorize')->willThrowException($exception);

        $eventManager->expects(self::exactly(2))
            ->method('trigger')
            ->withConsecutive(
                ['security.authorization.start', $user, []],
                ['security.authorization.failure', $user, ['error' => $message]]
            );

        $this->fixture->handle($request);
    }

    /**
     * @param string[] $options
     * @param string $expected
     *
     * @dataProvider sampleLoginPaths
     */
    public function testHandleReloadedUserDoesNotCallAuthorizerAuthorize(
        array $options,
        string $expected
    ): void {
        $this->setUpFixture($options);

        $path    = uniqid();
        $request = $this->createRequest($path);

        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($this->createUser());

        $this->authorizer->expects(self::never())->method('authorize');

        $this->context->expects(self::once())
            ->method('set')
            ->with('login.target', $path);

        $actual = $this->fixture->handle($request);

        self::assertInstanceOf(RedirectResponse::class, $actual);
        self::assertEquals(302, $actual->getStatusCode());
        self::assertEquals($expected, $actual->getHeaderLine('Location'));
    }

    /**
     * @param string[] $options
     * @param string $expected
     *
     * @dataProvider sampleLoginPaths
     */
    public function testHandleContextUserDoesNotCallAuthorizerAuthorize(
        array $options,
        string $expected
    ): void {
        $this->setUpFixture($options);

        $path    = uniqid();
        $request = $this->createRequest($path);

        $this->context->method('getRoles')->willReturn([uniqid()]);

        $this->authorizer->expects(self::never())->method('authorize');

        $this->context->expects(self::once())
            ->method('set')
            ->with('login.target', $path);

        $actual = $this->fixture->handle($request);

        self::assertInstanceOf(RedirectResponse::class, $actual);
        self::assertEquals(302, $actual->getStatusCode());
        self::assertEquals($expected, $actual->getHeaderLine('Location'));
    }

    public function testHandleNoRoles(): void
    {
        $request = $this->createRequest();

        $this->context->method('getRoles')->willReturn([]);

        $this->context->expects(self::never())->method('get');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function sampleLoginPaths(): array
    {
        $path = uniqid('/');

        return [
            'default login path' => [
                'options' => [],
                'expected' => '/login',
            ],
            'custom login path' => [
                'options' => ['login.path' => $path],
                'expected' => $path,
            ],
        ];
    }

    /**
     * @param string[] $options
     * @param string $path
     * @param string $expected
     *
     * @dataProvider sampleLogoutPaths
     */
    public function testHandleLogoutClearsContext(
        array $options,
        string $path,
        string $expected
    ): void {
        $this->setUpFixture($options);
        $request = $this->createRequest($path);

        $this->context->expects(self::never())->method('getRoles');
        $this->authorizer->expects(self::never())->method('authorize');
        $this->context->expects(self::once())->method('clear');

        $actual = $this->fixture->handle($request);

        self::assertInstanceOf(RedirectResponse::class, $actual);
        self::assertEquals(302, $actual->getStatusCode());
        self::assertEquals($expected, $actual->getHeaderLine('Location'));
    }

    public function sampleLogoutPaths(): array
    {
        $pathA = uniqid('/a');
        $pathB = uniqid('/b');

        return [
            'default logout path and target' => [
                'options' => [],
                'path' => '/logout',
                'expected' => '/',
            ],
            'custom logout path, default target' => [
                'options' => ['logout.path' => $pathA],
                'path' => $pathA,
                'expected' => '/',
            ],
            'default logout path, custom target' => [
                'options' => ['logout.target' => $pathA],
                'path' => '/logout',
                'expected' => $pathA,
            ],
            'custom logout path and target' => [
                'options' => ['logout.path' => $pathA, 'logout.target' => $pathB],
                'path' => $pathA,
                'expected' => $pathB,
            ],
        ];
    }

    public function testHandleLogoutTriggersEvent(): void
    {
        $request      = $this->createRequest('/logout');
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);
        $user         = $this->createUser();

        $this->fixture->setContainer($container);
        $this->context->method('get')->with('user')->willReturn($user);

        $eventManager->expects(self::exactly(1))
            ->method('trigger')
            ->with('security.logout', $user, []);

        $this->fixture->handle($request);
    }

    public function testHandleInvalidEventManagerSkipped(): void
    {
        $request   = $this->createRequest();
        $container = $this->createContainer(new \stdClass());

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($this->createUser());
        $this->authenticator->method('reloadUser')->willReturn($this->createUser());

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    /**
     * @param string[] $options
     * @param string[] $params
     * @param string $username
     * @param string $password
     *
     * @dataProvider sampleLoginParams
     */
    public function testHandleLoginCallsAuthenticatorAuthenticate(
        array $options,
        array $params,
        string $username,
        string $password
    ): void {
        $this->setUpFixture($options);
        $request = $this->createRequest('/login', $params);

        $this->authenticator->expects(self::once())
            ->method('authenticate')
            ->with($username, $password);

        $this->fixture->handle($request);
    }

    public function sampleLoginParams(): array
    {
        $userA = uniqid('a');
        $userB = uniqid('b');
        $passA = uniqid('a');
        $passB = uniqid('b');

        $fieldA = uniqid();
        $fieldB = uniqid();

        $params = [
            'username' => $userA,
            'password' => $passA,
            $fieldA => $userB,
            $fieldB => $passB,
        ];

        return [
            'default options' => [
                'options' => ['login.use_referrer' => false],
                'params' => $params,
                'username' => $userA,
                'password' => $passA,
            ],
            'custom options' => [
                'options' => [
                    'login.use_referrer' => false,
                    'login.username' => $fieldA,
                    'login.password' => $fieldB,
                ],
                'params' => $params,
                'username' => $userB,
                'password' => $passB,
            ],
        ];
    }

    public function testHandleLoginCallsContextSetUser(): void
    {
        $this->setUpFixture(['login.use_referrer' => false]);

        $params  = ['username' => uniqid(), 'password' => uniqid()];
        $request = $this->createRequest('/login', $params);
        $user    = $this->createUser();

        $this->authenticator->method('authenticate')->willReturn($user);

        $this->context->expects(self::once())
            ->method('set')
            ->with('user', $user);

        $this->fixture->handle($request);
    }

    public function testHandleLoginCallsEventManagerOnAuthenticate(): void
    {
        $this->setUpFixture(['login.use_referrer' => false]);

        $username     = uniqid();
        $params       = ['username' => $username, 'password' => uniqid()];
        $request      = $this->createRequest('/login', $params);
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);
        $user         = $this->createUser();

        $this->fixture->setContainer($container);
        $this->authenticator->method('authenticate')->willReturn($user);

        $eventManager->expects(self::exactly(2))
            ->method('trigger')
            ->withConsecutive(
                ['security.authentication.start', null, ['username' => $username]],
                ['security.authentication.success', $user, []]
            );

        $this->fixture->handle($request);
    }

    public function testHandleLoginAuthenticatorThrowsException(): void
    {
        $this->setUpFixture(['login.use_referrer' => false]);

        $username     = uniqid();
        $params       = ['username' => $username, 'password' => uniqid()];
        $request      = $this->createRequest('/login', $params);
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);

        $this->fixture->setContainer($container);

        $message   = uniqid();
        $exception = new AuthenticationException($message);
        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage($message);

        $this->authenticator->method('authenticate')->willThrowException($exception);

        $eventManager->expects(self::exactly(2))
            ->method('trigger')
            ->withConsecutive(
                ['security.authentication.start', null, ['username' => $username]],
                [
                    'security.authentication.failure',
                    null,
                    [
                        'username' => $username,
                        'error' => $message,
                    ],
                ]
            );

        $this->fixture->handle($request);
    }

    public function testHandleLoginResponse(): void
    {
        $this->setUpFixture(['login.use_referrer' => false]);

        $params  = ['username' => uniqid(), 'password' => uniqid()];
        $request = $this->createRequest('/login', $params);
        $user    = $this->createUser();

        $this->authenticator->method('authenticate')->willReturn($user);

        $this->context->expects(self::never())->method('get');

        $actual = $this->fixture->handle($request);

        self::assertInstanceOf(RedirectResponse::class, $actual);
        self::assertEquals(302, $actual->getStatusCode());
        self::assertEquals('/', $actual->getHeaderLine('Location'));
    }

    /**
     * @param string[] $options
     * @param string $expected
     *
     * @dataProvider sampleLoginTargets
     */
    public function testHandleLoginResponseWithReferrer(
        array $options,
        string $expected
    ): void {
        $this->setUpFixture($options);

        $params  = ['username' => uniqid(), 'password' => uniqid()];
        $request = $this->createRequest('/login', $params);
        $user    = $this->createUser();
        $target  = uniqid();

        $this->authenticator->method('authenticate')->willReturn($user);

        $this->context->expects(self::once())
            ->method('get')
            ->with('login.target', $expected)
            ->willReturn($target);

        $this->context->expects(self::once())
            ->method('remove')
            ->with('login.target');

        $actual = $this->fixture->handle($request);

        self::assertInstanceOf(RedirectResponse::class, $actual);
        self::assertEquals(302, $actual->getStatusCode());
        self::assertEquals($target, $actual->getHeaderLine('Location'));
    }

    public function sampleLoginTargets(): array
    {
        $path = uniqid('/');

        return [
            'default options' => [
                'options' => [],
                'expected' => '/',
            ],
            'custom options' => [
                'options' => ['login.target' => $path],
                'expected' => $path,
            ],
        ];
    }

    /**
     * @param string|null $username
     * @param string|null $password
     *
     * @dataProvider sampleUsernameAndPassword
     */
    public function testHandleLoginInvalidDataDoesNotCallAuthenticatorAuthenticate(
        ?string $username,
        ?string $password
    ): void {
        $params  = ['username' => $username, 'password' => $password];
        $request = $this->createRequest('/login', $params);

        $this->authenticator->expects(self::never())->method('authenticate');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function sampleUsernameAndPassword(): array
    {
        return [
            'no password' => [
                'username' => uniqid(),
                'password' => null,
            ],
            'empty password' => [
                'username' => uniqid(),
                'password' => '',
            ],
            'false password' => [
                'username' => uniqid(),
                'password' => false,
            ],
            'no username' => [
                'username' => null,
                'password' => uniqid(),
            ],
            'empty username' => [
                'username' => '',
                'password' => uniqid(),
            ],
            'false username' => [
                'username' => false,
                'password' => uniqid(),
            ],
            'both null' => [
                'username' => null,
                'password' => null,
            ],
            'both empty' => [
                'username' => '',
                'password' => '',
            ],
            'both false' => [
                'username' => false,
                'password' => false,
            ],
            'mixed' => [
                'username' => false,
                'password' => '',
            ],
        ];
    }

    /**
     * @param mixed $params
     *
     * @dataProvider sampleInvalidParams
     */
    public function testHandleLoginNonArrayParams($params): void
    {
        $request = $this->createRequest('/login', $params);

        $this->authenticator->expects(self::never())->method('authenticate');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function sampleInvalidParams(): array
    {
        return [
            'null' => [null],
            'string' => [uniqid()],
            'int' => [rand()],
            'bool' => [(bool) rand(0, 1)],
        ];
    }

    /**
     * @param string[] $options
     * @param string $path
     *
     * @dataProvider sampleLoginPaths
     */
    public function testHandleLoginNonPost(
        array $options,
        string $path
    ): void {
        $this->setUpFixture($options);
        $request = $this->createRequest($path, [], uniqid());

        $this->authenticator->expects(self::never())->method('authenticate');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function testGetDefaultConfig(): void
    {
        $actual = $this->fixture->getDefaultConfig();

        $expected = [
            'login.path' => '/login',
            'login.path_post' => '/login',
            'login.target' => '/',
            'login.username' => 'username',
            'login.password' => 'password',
            'login.use_referrer' => true,
            'logout.path' => '/logout',
            'logout.target' => '/',
        ];
        self::assertEquals($expected, $actual);
    }

    /**
     * @param string $path
     * @param mixed $params
     * @param string $method
     *
     * @return ServerRequestInterface
     */
    protected function createRequest(
        string $path = '',
        $params = [],
        string $method = 'POST'
    ): ServerRequestInterface {
        $uri = $this->createConfiguredMock(
            UriInterface::class,
            ['getPath' => $path]
        );

        return $this->createConfiguredMock(
            ServerRequestInterface::class,
            [
                'getMethod' => $method,
                'getUri' => $uri,
                'getParsedBody' => $params,
            ]
        );
    }

    /**
     * @return UserInterface
     */
    protected function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }

    /**
     * @param mixed $eventManager
     *
     * @return ContainerInterface
     */
    protected function createContainer($eventManager = null): ContainerInterface
    {
        $container = $this->createMock(ContainerInterface::class);

        $container->method('has')->willReturnMap(
            [
                ['event.manager', !!$eventManager],
            ]
        );

        $container->method('get')->willReturnMap(
            [
                ['event.manager', $eventManager],
            ]
        );

        return $container;
    }

    /**
     * @return EventManagerInterface|MockObject
     */
    protected function createEventManager(): EventManagerInterface
    {
        return $this->createMock(EventManagerInterface::class);
    }

    /**
     * @param mixed[] $options
     */
    protected function setUpFixture(array $options = []): void
    {
        $this->fixture = new FormShield(
            $this->context,
            $this->authenticator,
            $this->authorizer,
            $options
        );
    }
}
