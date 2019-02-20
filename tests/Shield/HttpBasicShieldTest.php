<?php

namespace Bitty\Tests\Security\Shield;

use Bitty\EventManager\EventManagerInterface;
use Bitty\Security\Authentication\AuthenticatorInterface;
use Bitty\Security\Authorization\AuthorizerInterface;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\Exception\AuthorizationException;
use Bitty\Security\Shield\AbstractShield;
use Bitty\Security\Shield\HttpBasicShield;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class HttpBasicShieldTest extends TestCase
{
    /**
     * @var HttpBasicShield
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

    public function testHandleCallsAuthenticatorAuthenticate(): void
    {
        $username = uniqid();
        $password = uniqid();
        $request  = $this->createRequest($username, $password);

        $this->context->method('getRoles')->willReturn([uniqid()]);

        $this->authenticator->expects(self::once())
            ->method('authenticate')
            ->with($username, $password);

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function testHandleCallsContextSetUser(): void
    {
        $request = $this->createRequest(uniqid(), uniqid());
        $user    = $this->createUser();

        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->authenticator->method('authenticate')->willReturn($user);

        $this->context->expects(self::once())
            ->method('set')
            ->with('user', $user);

        $this->fixture->handle($request);
    }

    public function testHandleCallsEventManagerOnAuthenticate(): void
    {
        $username     = uniqid();
        $request      = $this->createRequest($username, uniqid());
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);
        $user         = $this->createUser();

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->authenticator->method('authenticate')->willReturn($user);

        $eventManager->expects(self::exactly(4))
            ->method('trigger')
            ->withConsecutive(
                ['security.authentication.start', null, ['username' => $username]],
                ['security.authentication.success', $user, []],
                ['security.authorization.start', $user, []],
                ['security.authorization.success', $user, []]
            );

        $this->fixture->handle($request);
    }

    public function testHandleAuthenticatorThrowsException(): void
    {
        $username     = uniqid();
        $request      = $this->createRequest($username, uniqid());
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);

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

    public function testHandleAuthenticatedUserCallsAuthorizerAuthorize(): void
    {
        $request = $this->createRequest(uniqid(), uniqid());
        $user    = $this->createUser();
        $roles   = [uniqid()];

        $this->context->method('getRoles')->willReturn($roles);
        $this->authenticator->method('authenticate')->willReturn($user);

        $this->authorizer->expects(self::once())
            ->method('authorize')
            ->with($user, $roles);

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function testHandleAuthorizerThrowsException(): void
    {
        $username     = uniqid();
        $request      = $this->createRequest($username, uniqid());
        $user         = $this->createUser();
        $eventManager = $this->createEventManager();
        $container    = $this->createContainer($eventManager);

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->authenticator->method('authenticate')->willReturn($user);

        $message   = uniqid();
        $exception = new AuthorizationException($message);
        self::expectException(AuthorizationException::class);
        self::expectExceptionMessage($message);

        $this->authorizer->method('authorize')->willThrowException($exception);

        $eventManager->expects(self::exactly(4))
            ->method('trigger')
            ->withConsecutive(
                ['security.authentication.start', null, ['username' => $username]],
                ['security.authentication.success', $user, []],
                ['security.authorization.start', $user, []],
                ['security.authorization.failure', $user, ['error' => $message]]
            );

        $this->fixture->handle($request);
    }

    public function testHandleReloadedUserDoesNotCallAuthenticatorAuthenticate(): void
    {
        $request = $this->createRequest();

        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->context->method('get')->with('user')->willReturn($this->createUser());
        $this->authenticator->method('reloadUser')->willReturn($this->createUser());

        $this->authenticator->expects(self::never())->method('authenticate');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
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

    public function testHandleInvalidEventManagerSkipped(): void
    {
        $request   = $this->createRequest(uniqid(), uniqid());
        $container = $this->createContainer(new \stdClass());

        $this->fixture->setContainer($container);
        $this->context->method('getRoles')->willReturn([uniqid()]);
        $this->authenticator->method('authenticate')->willReturn($this->createUser());

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    /**
     * @param string|null $username
     * @param string|null $password
     *
     * @dataProvider sampleUsernameAndPassword
     */
    public function testHandleInvalidDataDoesNotCallAuthenticatorAuthenticate(
        ?string $username,
        ?string $password
    ): void {
        $request = $this->createRequest($username, $password);

        $this->context->method('getRoles')->willReturn([uniqid()]);

        $this->authenticator->expects(self::never())->method('authenticate');

        $actual = $this->fixture->handle($request);

        $this->assertResponse($actual);
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
     * @param array $options
     * @param string $realm
     *
     * @dataProvider sampleRealms
     */
    public function testHandleResponse(array $options, string $realm): void
    {
        $request = $this->createRequest();

        $this->setUpFixture($options);

        $this->context->method('getRoles')->willReturn([uniqid()]);

        $actual = $this->fixture->handle($request);

        $this->assertResponse($actual, $realm);
    }

    public function sampleRealms(): array
    {
        $realm = uniqid();

        return [
            'default' => [[], 'Secured Area'],
            'custom' => [['realm' => $realm], $realm],
        ];
    }

    public function testHandleNoRoles(): void
    {
        $request = $this->createRequest();

        $this->context->method('getRoles')->willReturn([]);

        $this->context->expects(self::never())->method('get');

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    /**
     * @param ResponseInterface|null $response
     * @param string $realm
     */
    protected function assertResponse(
        ?ResponseInterface $response,
        string $realm = 'Secured Area'
    ): void {
        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals('', (string) $response->getBody());
        self::assertEquals(401, $response->getStatusCode());
        self::assertEquals(
            ['WWW-Authenticate' => ['Basic realm="'.$realm.'"']],
            $response->getHeaders()
        );
    }

    /**
     * @param string|null $username
     * @param string|null $password
     *
     * @return ServerRequestInterface
     */
    protected function createRequest(
        ?string $username = null,
        ?string $password = null
    ): ServerRequestInterface {
        return $this->createConfiguredMock(
            ServerRequestInterface::class,
            [
                'getServerParams' => [
                    'PHP_AUTH_USER' => $username,
                    'PHP_AUTH_PW' => $password,
                ],
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
        $this->fixture = new HttpBasicShield(
            $this->context,
            $this->authenticator,
            $this->authorizer,
            $options
        );
    }
}
