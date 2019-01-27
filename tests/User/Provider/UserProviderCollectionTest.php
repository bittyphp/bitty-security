<?php

namespace Bitty\Tests\Security\User\Provider;

use Bitty\Security\User\Provider\UserProviderInterface;
use Bitty\Security\User\Provider\UserProviderCollection;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\TestCase;

class UserProviderCollectionTest extends TestCase
{
    /**
     * @var UserProviderCollection
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new UserProviderCollection();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(UserProviderInterface::class, $this->fixture);
    }

    public function testGetUserCallsProvider(): void
    {
        $username  = uniqid();
        $providerA = $this->createUserProvider();
        $providerB = $this->createUserProvider();
        $providerC = $this->createUserProvider();

        $this->fixture->add($providerA);
        $this->fixture->add($providerB);
        $this->fixture->add($providerC);

        $user = $this->createMock(UserInterface::class);
        $providerA->expects(self::once())->method('getUser')->with($username);
        $providerC->expects(self::never())->method('getUser');
        $providerB->expects(self::once())
            ->method('getUser')
            ->with($username)
            ->willReturn($user);

        $actual = $this->fixture->getUser($username);

        self::assertSame($user, $actual);
    }

    public function testGetUserNoProviderResponse(): void
    {
        $username  = uniqid();
        $providerA = $this->createUserProvider();
        $providerB = $this->createUserProvider();
        $providerC = $this->createUserProvider();

        $this->fixture->add($providerA);
        $this->fixture->add($providerB);
        $this->fixture->add($providerC);

        $providerA->expects(self::once())->method('getUser')->with($username);
        $providerB->expects(self::once())->method('getUser')->with($username);
        $providerC->expects(self::once())->method('getUser')->with($username);

        $actual = $this->fixture->getUser($username);

        self::assertNull($actual);
    }

    public function testGetUserNoProviders(): void
    {
        $actual = $this->fixture->getUser(uniqid());

        self::assertNull($actual);
    }

    public function testGetUserConstructorProviders(): void
    {
        $username  = uniqid();
        $providerA = $this->createUserProvider();
        $providerB = $this->createUserProvider();
        $providerC = $this->createUserProvider();

        $this->fixture = new UserProviderCollection([$providerA, $providerB]);
        $this->fixture->add($providerC);

        $providerA->expects(self::once())->method('getUser')->with($username);
        $providerB->expects(self::once())->method('getUser')->with($username);
        $providerC->expects(self::once())->method('getUser')->with($username);

        $this->fixture->getUser($username);
    }

    /**
     * @return UserProviderInterface
     */
    protected function createUserProvider(): UserProviderInterface
    {
        return $this->createMock(UserProviderInterface::class);
    }
}
