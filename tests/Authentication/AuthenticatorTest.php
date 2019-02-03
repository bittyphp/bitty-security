<?php

namespace Bitty\Tests\Security\Authentication;

use Bitty\Security\Authentication\Authenticator;
use Bitty\Security\Authentication\AuthenticatorInterface;
use Bitty\Security\Encoder\EncoderInterface;
use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\User\Provider\UserProviderInterface;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase
{
    /**
     * @var Authenticator
     */
    private $fixture = null;

    /**
     * @var UserProviderInterface|MockObject
     */
    private $userProvider = null;

    /**
     * @var EncoderInterface|MockObject
     */
    private $encoder = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->userProvider = $this->createMock(UserProviderInterface::class);
        $this->encoder      = $this->createMock(EncoderInterface::class);

        $this->fixture = new Authenticator($this->userProvider, $this->encoder);
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AuthenticatorInterface::class, $this->fixture);
    }

    public function testAuthenticateCallsUserProvider(): void
    {
        $username = uniqid();

        $this->encoder->method('verify')->willReturn(true);

        $this->userProvider->expects(self::once())
            ->method('getUser')
            ->with($username)
            ->willReturn($this->createUser());

        $this->fixture->authenticate($username, uniqid());
    }

    public function testAuthenticateCallsEncoder(): void
    {
        $password = uniqid();
        $salt     = uniqid();
        $hash     = uniqid();
        $user     = $this->createUser('', $hash, $salt);

        $this->userProvider->method('getUser')->willReturn($user);

        $this->encoder->expects(self::once())
            ->method('verify')
            ->with($hash, $password, $salt)
            ->willReturn(true);

        $this->fixture->authenticate(uniqid(), $password);
    }

    public function testAuthenticateThrowsInvalidPasswordException(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid password.');

        $this->encoder->method('verify')->willReturn(false);
        $this->userProvider->method('getUser')->willReturn($this->createUser());

        $this->fixture->authenticate(uniqid(), uniqid());
    }

    public function testAuthenticateThrowsInvalidUsernameException(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid username.');

        $this->fixture->authenticate(uniqid(), uniqid());
    }

    public function testAuthenticateReturnsUser(): void
    {
        $user = $this->createUser();

        $this->userProvider->method('getUser')->willReturn($user);
        $this->encoder->method('verify')->willReturn(true);

        $actual = $this->fixture->authenticate(uniqid(), uniqid());

        self::assertSame($user, $actual);
    }

    public function testReloadUserCallsUserProvider(): void
    {
        $username = uniqid();
        $user     = $this->createUser($username);

        $this->userProvider->expects(self::once())
            ->method('getUser')
            ->with($username);

        $this->fixture->reloadUser($user);
    }

    public function testReloadUserReturnsNull(): void
    {
        $user = $this->createUser();

        $this->userProvider->method('getUser')->willReturn(null);

        $actual = $this->fixture->reloadUser($user);

        self::assertNull($actual);
    }

    public function testReloadUserReturnsUser(): void
    {
        $hash  = uniqid();
        $salt  = uniqid();
        $userA = $this->createUser(uniqid(), $hash, $salt);
        $userB = $this->createUser(uniqid(), $hash, $salt);

        $this->userProvider->method('getUser')->willReturn($userB);

        $actual = $this->fixture->reloadUser($userA);

        self::assertSame($userB, $actual);
    }

    public function testReloadUserWithMismatchSalts(): void
    {
        $hash  = uniqid();
        $userA = $this->createUser(uniqid(), $hash, uniqid());
        $userB = $this->createUser(uniqid(), $hash, uniqid());

        $this->userProvider->method('getUser')->willReturn($userB);

        $actual = $this->fixture->reloadUser($userA);

        self::assertNull($actual);
    }

    public function testReloadUserWithMismatchPasswords(): void
    {
        $salt  = uniqid();
        $userA = $this->createUser(uniqid(), uniqid(), $salt);
        $userB = $this->createUser(uniqid(), uniqid(), $salt);

        $this->userProvider->method('getUser')->willReturn($userB);

        $actual = $this->fixture->reloadUser($userA);

        self::assertNull($actual);
    }

    /**
     * @param string $username
     * @param string $hash
     * @param string $salt
     *
     * @return UserInterface|MockObject
     */
    private function createUser(
        string $username = '',
        string $hash = '',
        string $salt = ''
    ): UserInterface {
        return $this->createConfiguredMock(
            UserInterface::class,
            [
                'getUsername' => $username,
                'getPassword' => $hash,
                'getSalt' => $salt,
            ]
        );
    }
}
