<?php

namespace Bitty\Tests\Security\Context;

use Bitty\Security\Context\ContextCollection;
use Bitty\Security\Context\ContextInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class ContextCollectionTest extends TestCase
{
    /**
     * @var ContextCollection
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new ContextCollection();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ContextInterface::class, $this->fixture);
    }

    public function testIsDefaultTrue(): void
    {
        $contextA = $this->createContext(false);
        $contextB = $this->createContext(true);
        $contextC = $this->createContext(false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('isDefault');
        $contextB->expects(self::once())->method('isDefault');
        $contextC->expects(self::never())->method('isDefault');

        $actual = $this->fixture->isDefault();

        self::assertTrue($actual);
    }

    public function testIsDefaultFalse(): void
    {
        $contextA = $this->createContext(false);
        $contextB = $this->createContext(false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('isDefault');
        $contextB->expects(self::once())->method('isDefault');

        $actual = $this->fixture->isDefault();

        self::assertFalse($actual);
    }

    public function testCantAddSameContextTwice(): void
    {
        $context = $this->createContext();

        $this->fixture->add($context);
        $this->fixture->add($context);

        $context->expects(self::once())->method('isDefault');

        $this->fixture->isDefault();
    }

    public function testIsDefaultNoContexts(): void
    {
        $actual = $this->fixture->isDefault();

        self::assertFalse($actual);
    }

    public function testIsDefaultClearsActiveContext(): void
    {
        $name     = uniqid();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isShielded($request);
        $this->fixture->isDefault();
        $this->fixture->get($name, uniqid());
    }

    public function testGetReturnsDefault(): void
    {
        $name    = uniqid();
        $default = uniqid();

        $contextA = $this->createContext();
        $contextB = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $actual = $this->fixture->get($name, $default);

        self::assertEquals($default, $actual);
    }

    public function testGetReturnsNonNull(): void
    {
        $name  = uniqid();
        $value = uniqid();

        $contextA = $this->createContext();
        $contextB = $this->createContext();
        $contextC = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('get')->willReturn(null);
        $contextB->expects(self::once())->method('get')->willReturn($value);
        $contextC->expects(self::never())->method('get');

        $actual = $this->fixture->get($name, uniqid());

        self::assertEquals($value, $actual);
    }

    public function testGetReturnsActiveContext(): void
    {
        $name    = uniqid();
        $value   = uniqid();
        $default = uniqid();

        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, true);
        $contextC = $this->createContext(false, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);
        $this->fixture->isShielded($this->createRequest());

        $contextA->expects(self::never())->method('get');
        $contextC->expects(self::never())->method('get');
        $contextB->expects(self::once())
            ->method('get')
            ->with($name, $default)
            ->willReturn($value);

        $actual = $this->fixture->get($name, $default);

        self::assertEquals($value, $actual);
    }

    public function testClearActiveContext(): void
    {
        $name = uniqid();

        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->isShielded($this->createRequest());
        $this->fixture->clearActiveContext();

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->get($name, uniqid());
    }

    public function testSet(): void
    {
        $name  = uniqid();
        $value = uniqid();

        $contextA = $this->createContext();
        $contextB = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('set')->with($name, $value);
        $contextB->expects(self::once())->method('set')->with($name, $value);

        $this->fixture->set($name, $value);
    }

    public function testSetClearsActiveContext(): void
    {
        $name     = uniqid();
        $contextA = $this->createContext(false);
        $contextB = $this->createContext(true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isDefault();
        $this->fixture->set(uniqid(), uniqid());
        $this->fixture->get($name, uniqid());
    }

    public function testRemove(): void
    {
        $name = uniqid();

        $contextA = $this->createContext();
        $contextB = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('remove')->with($name);
        $contextB->expects(self::once())->method('remove')->with($name);

        $this->fixture->remove($name);
    }

    public function testRemoveClearsActiveContext(): void
    {
        $name     = uniqid();
        $contextA = $this->createContext(false);
        $contextB = $this->createContext(true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isDefault();
        $this->fixture->remove(uniqid());
        $this->fixture->get($name, uniqid());
    }

    public function testClear(): void
    {
        $contextA = $this->createContext();
        $contextB = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('clear');
        $contextB->expects(self::once())->method('clear');

        $this->fixture->clear();
    }

    public function testClearClearsActiveContext(): void
    {
        $name     = uniqid();
        $contextA = $this->createContext(false);
        $contextB = $this->createContext(true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isDefault();
        $this->fixture->clear();
        $this->fixture->get($name, uniqid());
    }

    public function testIsShieldedTrue(): void
    {
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, true);
        $contextC = $this->createContext(false, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('isShielded')->with($request);
        $contextB->expects(self::once())->method('isShielded')->with($request);
        $contextC->expects(self::never())->method('isShielded');

        $actual = $this->fixture->isShielded($request);

        self::assertTrue($actual);
    }

    public function testIsShieldedFalse(): void
    {
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, false);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('isShielded')->with($request);
        $contextB->expects(self::once())->method('isShielded')->with($request);

        $actual = $this->fixture->isShielded($request);

        self::assertFalse($actual);
    }

    public function testIsShieldedSetsActiveContext(): void
    {
        $name     = uniqid();
        $default  = uniqid();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(false, true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('isShielded')->with($request);
        $contextB->expects(self::once())->method('isShielded')->with($request);
        $contextA->expects(self::never())->method('get');
        $contextB->expects(self::once())->method('get')->with($name, $default);

        $this->fixture->isShielded($request);
        $this->fixture->get($name, $default);
    }

    public function testIsShieldedClearsActiveContext(): void
    {
        $name     = uniqid();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(true, false, [uniqid()]);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isDefault();
        $this->fixture->isShielded($request);
        $this->fixture->get($name, uniqid());
    }

    public function testGetPatternMatch(): void
    {
        $match    = [uniqid()];
        $request  = $this->createRequest();
        $contextA = $this->createContext();
        $contextB = $this->createContext(false, false, $match);
        $contextC = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);
        $this->fixture->add($contextC);

        $contextA->expects(self::once())->method('getPatternMatch')->with($request);
        $contextB->expects(self::once())->method('getPatternMatch')->with($request);
        $contextC->expects(self::never())->method('getPatternMatch');

        $actual = $this->fixture->getPatternMatch($request);

        self::assertEquals($match, $actual);
    }

    public function testGetPatternMatchNoMatches(): void
    {
        $request  = $this->createRequest();
        $contextA = $this->createContext();
        $contextB = $this->createContext();

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('getPatternMatch')->with($request);
        $contextB->expects(self::once())->method('getPatternMatch')->with($request);

        $actual = $this->fixture->getPatternMatch($request);

        self::assertEquals([], $actual);
    }

    public function testGetPatternMatchSetsActiveContext(): void
    {
        $name     = uniqid();
        $default  = uniqid();
        $request  = $this->createRequest();
        $contextA = $this->createContext();
        $contextB = $this->createContext(false, false, [uniqid()]);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::never())->method('get');
        $contextB->expects(self::once())->method('get')->with($name, $default);

        $this->fixture->getPatternMatch($request);
        $this->fixture->get($name, $default);
    }

    public function testGetPatternMatchClearsActiveContext(): void
    {
        $name     = uniqid();
        $request  = $this->createRequest();
        $contextA = $this->createContext(false, false);
        $contextB = $this->createContext(true, true);

        $this->fixture->add($contextA);
        $this->fixture->add($contextB);

        $contextA->expects(self::once())->method('get')->with($name, null);
        $contextB->expects(self::once())->method('get')->with($name, null);

        $this->fixture->isDefault();
        $this->fixture->getPatternMatch($request);
        $this->fixture->get($name, uniqid());
    }

    /**
     * @param bool $isDefault
     * @param bool $isShielded
     * @param array $match
     *
     * @return ContextInterface|MockObject
     */
    protected function createContext(
        bool $isDefault = false,
        bool $isShielded = false,
        array $match = []
    ): ContextInterface {
        return $this->createConfiguredMock(
            ContextInterface::class,
            [
                'isDefault' => $isDefault,
                'isShielded' => $isShielded,
                'getPatternMatch' => $match,
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
}
