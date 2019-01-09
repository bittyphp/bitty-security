<?php

namespace Bitty\Tests\Security\Authorization;

use Bitty\Security\Authorization\Authorizer;
use Bitty\Security\Authorization\AuthorizerInterface;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AuthorizerTest extends TestCase
{
    /**
     * @var Authorizer
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new Authorizer();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AuthorizerInterface::class, $this->fixture);
    }

    public function testAuthorize(): void
    {
        $user = $this->createUser();

        $actual = $this->fixture->authorize($user, []);

        self::assertTrue($actual);
    }

    /**
     * @return UserInterface|MockObject
     */
    protected function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }
}
