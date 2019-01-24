<?php

namespace Bitty\Tests\Security\Context;

use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Context\ContextMap;
use Bitty\Security\Context\ContextMapInterface;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class ContextMapTest extends TestCase
{
    /**
     * @var ContextMap
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new ContextMap();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ContextMapInterface::class, $this->fixture);
    }

    public function testNoContexts(): void
    {
        $request = $this->createRequest();

        $actual = $this->fixture->getUser($request);

        self::assertNull($actual);
    }

    public function testCallsIsShielded(): void
    {
        $request  = $this->createRequest();
        $contextA = $this->createContext(true, false);
        $contextB = $this->createContext(true, true);
        $contextC = $this->createContext(true, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('isShielded')->with($request);
        $contextB->expects(self::once())->method('isShielded')->with($request);
        $contextC->expects(self::never())->method('isShielded');

        $this->fixture->getUser($request);
    }

    public function testShieldedContextGetsUser(): void
    {
        $user     = $this->createUser();
        $request  = $this->createRequest();
        $contextA = $this->createContext(true, false);
        $contextB = $this->createContext(true, true);
        $contextC = $this->createContext(true, true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::never())->method('get');
        $contextC->expects(self::never())->method('get');
        $contextB->expects(self::once())
            ->method('get')
            ->with('user', null)
            ->willReturn($user);

        $actual = $this->fixture->getUser($request);

        self::assertSame($user, $actual);
    }

    public function testCallsIsDefault(): void
    {
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(true, false);
        $contextC = $this->createContext(true, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('isDefault');
        $contextB->expects(self::once())->method('isDefault');
        $contextC->expects(self::never())->method('isDefault');

        $this->fixture->getUser($request);
    }

    public function testDefaultContextGetsUser(): void
    {
        $user     = $this->createUser();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(true, false);
        $contextC = $this->createContext(true, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::never())->method('get');
        $contextC->expects(self::never())->method('get');
        $contextB->expects(self::once())
            ->method('get')
            ->with('user', null)
            ->willReturn($user);

        $actual = $this->fixture->getUser($request);

        self::assertSame($user, $actual);
    }

    public function testFirstContextGetsUser(): void
    {
        $user     = $this->createUser();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, false);
        $contextC = $this->createContext(false, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextB->expects(self::never())->method('get');
        $contextC->expects(self::never())->method('get');
        $contextA->expects(self::once())
            ->method('get')
            ->with('user', null)
            ->willReturn($user);

        $actual = $this->fixture->getUser($request);

        self::assertSame($user, $actual);
    }

    /**
     * @param bool $isDefault
     * @param bool $isShielded
     *
     * @return ContextInterface|MockObject
     */
    protected function createContext(
        bool $isDefault = false,
        bool $isShielded = false
    ): ContextInterface {
        return $this->createConfiguredMock(
            ContextInterface::class,
            [
                'isDefault' => $isDefault,
                'isShielded' => $isShielded,
            ]
        );
    }

    /**
     * @return ServerRequestInterface
     */
    protected function createRequest(): ServerRequestInterface
    {
        return $this->createMock(ServerRequestInterface::class);
    }

    /**
     * @return UserInterface
     */
    protected function createUser(): UserInterface
    {
        return $this->createMock(UserInterface::class);
    }
}
