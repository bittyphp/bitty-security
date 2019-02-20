<?php

namespace Bitty\Tests\Security\Shield;

use Bitty\Container\ContainerAwareInterface;
use Bitty\Security\Context\ContextCollection;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Shield\ShieldCollection;
use Bitty\Security\Shield\ShieldInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ShieldCollectionTest extends TestCase
{
    /**
     * @var ShieldCollection
     */
    protected $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new ShieldCollection();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ShieldInterface::class, $this->fixture);
        self::assertInstanceOf(ContainerAwareInterface::class, $this->fixture);
    }

    public function testSetContainerNull(): void
    {
        $this->fixture->setContainer(null);
        $actual = $this->fixture->getContainer();

        self::assertNull($actual);
    }

    public function testSetContainer(): void
    {
        $container = $this->createContainer();

        $this->fixture->setContainer($container);
        $actual = $this->fixture->getContainer();

        self::assertSame($container, $actual);
    }

    public function testSetContainerSetsShieldContainers(): void
    {
        $container = $this->createContainer();

        $shieldA = $this->createContainerAwareShield();
        $shieldB = $this->createShield();
        $shieldC = $this->createContainerAwareShield();

        $this->fixture->add($shieldA);
        $this->fixture->add($shieldB);
        $this->fixture->add($shieldC);

        $shieldA->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $shieldC->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $this->fixture->setContainer($container);
    }

    public function testConstructorSetContainerSetsShieldContainers(): void
    {
        $container = $this->createContainer();

        $shieldA = $this->createContainerAwareShield();
        $shieldB = $this->createShield();
        $shieldC = $this->createContainerAwareShield();

        $this->fixture = new ShieldCollection([$shieldA, $shieldB, $shieldC]);

        $shieldA->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $shieldC->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $this->fixture->setContainer($container);
    }

    public function testAddSetsShieldContainers(): void
    {
        $container = $this->createContainer();
        $shield    = $this->createContainerAwareShield();

        $this->fixture->setContainer($container);

        $shield->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $this->fixture->add($shield);
    }

    public function testGetContext(): void
    {
        $context = $this->createContext(true);
        $shield  = $this->createShield($context);

        $this->fixture->add($shield);

        $actual = $this->fixture->getContext();

        self::assertInstanceOf(ContextCollection::class, $actual);
        self::assertTrue($actual->isDefault());
    }

    public function testHandleNoShields(): void
    {
        $request = $this->createRequest();

        $actual = $this->fixture->handle($request);

        self::assertNull($actual);
    }

    public function testHandleOneShield(): void
    {
        $request  = $this->createRequest();
        $response = $this->createResponse();
        $shield   = $this->createShield();

        $this->fixture->add($shield);

        $shield->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $actual = $this->fixture->handle($request);

        self::assertSame($response, $actual);
    }

    public function testHandleMultipleShields(): void
    {
        $request  = $this->createRequest();
        $response = $this->createResponse();
        $shieldA  = $this->createShield();
        $shieldB  = $this->createShield();
        $shieldC  = $this->createShield();

        $this->fixture->add($shieldA);
        $this->fixture->add($shieldB);
        $this->fixture->add($shieldC);

        $shieldA->expects(self::once())
            ->method('handle')
            ->with($request);

        $shieldB->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $shieldC->expects(self::never())->method('handle');

        $actual = $this->fixture->handle($request);

        self::assertSame($response, $actual);
    }

    /**
     * @return ContainerInterface
     */
    protected function createContainer(): ContainerInterface
    {
        return $this->createMock(ContainerInterface::class);
    }

    /**
     * @param bool $isDefault
     *
     * @return ContextInterface
     */
    protected function createContext(bool $isDefault = false): ContextInterface
    {
        return $this->createConfiguredMock(
            ContextInterface::class,
            ['isDefault' => $isDefault]
        );
    }

    /**
     * @param ContextInterface|null $context
     *
     * @return ShieldInterface|MockObject
     */
    protected function createShield(?ContextInterface $context = null): ShieldInterface
    {
        return $this->createConfiguredMock(
            ShieldInterface::class,
            [
                'getContext' => $context ?? $this->createContext(),
            ]
        );
    }

    /**
     * @return ShieldInterface|MockObject
     */
    protected function createContainerAwareShield(): ShieldInterface
    {
        /** @var ShieldInterface|MockObject $shield */
        $shield = $this->createMock([ShieldInterface::class, ContainerAwareInterface::class]);

        return $shield;
    }

    /**
     * @return ServerRequestInterface
     */
    protected function createRequest(): ServerRequestInterface
    {
        return $this->createMock(ServerRequestInterface::class);
    }

    /**
     * @return ResponseInterface
     */
    protected function createResponse(): ResponseInterface
    {
        return $this->createMock(ResponseInterface::class);
    }
}
