<?php

namespace Bitty\Tests\Security;

use Bitty\Container\ContainerAwareInterface;
use Bitty\Container\ContainerInterface;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Context\ContextMapInterface;
use Bitty\Security\Context\ContextMapServiceProvider;
use Bitty\Security\SecurityMiddleware;
use Bitty\Security\Shield\ShieldInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class SecurityMiddlewareTest extends TestCase
{
    /**
     * @var SecurityMiddleware
     */
    protected $fixture = null;

    /**
     * @var ShieldInterface|MockObject
     */
    protected $shield = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->shield = $this->createMock(ShieldInterface::class);

        $this->fixture = new SecurityMiddleware($this->shield);
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(MiddlewareInterface::class, $this->fixture);
        self::assertInstanceOf(ContainerAwareInterface::class, $this->fixture);
    }

    public function testGetContainer(): void
    {
        $container = $this->createMock(PsrContainerInterface::class);

        $this->fixture->setContainer($container);

        $actual = $this->fixture->getContainer();

        self::assertSame($container, $actual);
    }

    public function testGetNullContainer(): void
    {
        $this->fixture->setContainer(null);

        $actual = $this->fixture->getContainer();

        self::assertNull($actual);
    }

    public function testGetContainerWithoutSet(): void
    {
        $actual = $this->fixture->getContainer();

        self::assertNull($actual);
    }

    public function testSetContainerRegistersContextMap(): void
    {
        $container = $this->createContainer();

        $spy = self::once();
        $container->expects($spy)->method('register');

        $this->fixture->setContainer($container);

        $actual = $spy->getInvocations()[0]->getParameters()[0];

        self::assertIsArray($actual);
        self::assertCount(1, $actual);
        self::assertInstanceOf(ContextMapServiceProvider::class, $actual[0]);
    }

    public function testSetContainerAddsContextToMap(): void
    {
        $contextMap = $this->createMock(ContextMapInterface::class);
        $container  = $this->createContainer($contextMap);

        $context = $this->createMock(ContextInterface::class);
        $this->shield->method('getContext')->willReturn($context);

        $contextMap->expects(self::once())
            ->method('add')
            ->with($context);

        $this->fixture->setContainer($container);
    }

    public function testSetContainerUpdatesContainerAwareShield(): void
    {
        $container = $this->createContainer();

        /**
         * @var ShieldInterface|MockObject
         */
        $shield = $this->createMock([ShieldInterface::class, ContainerAwareInterface::class]);

        $fixture = new SecurityMiddleware($shield);

        $shield->expects(self::once())
            ->method('setContainer')
            ->with($container);

        $fixture->setContainer($container);
    }

    public function testSetContainerDoesNotUpdateNonContainerAwareShield(): void
    {
        $container = $this->createContainer();

        $spy = self::once();
        $this->shield->expects($spy)->method(self::anything());

        $this->fixture->setContainer($container);

        $methods = [];
        foreach ($spy->getInvocations() as $invocation) {
            $methods[] = $invocation->getMethodName();
        }

        self::assertEquals(['getContext'], $methods);
    }

    public function testSetContainerWithGenericContainer(): void
    {
        $container = $this->createMock(PsrContainerInterface::class);

        $container->expects(self::never())->method(self::anything());

        $this->fixture->setContainer($container);
    }

    public function testProcessCallsShieldHandle(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $this->shield->expects(self::once())
            ->method('handle')
            ->with($request);

        $this->fixture->process($request, $handler);
    }

    public function testProcessCallsHandlerHandle(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $this->shield->method('handle')->willReturn(null);

        $handler->expects(self::once())
            ->method('handle')
            ->with($request);

        $this->fixture->process($request, $handler);
    }

    public function testProcessReturnsShieldResponse(): void
    {
        $request  = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $handler  = $this->createMock(RequestHandlerInterface::class);

        $this->shield->method('handle')->willReturn($response);

        $handler->expects(self::never())->method('handle');

        $actual = $this->fixture->process($request, $handler);

        self::assertSame($response, $actual);
    }

    public function testProcessReturnsHandlerResponse(): void
    {
        $request  = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $handler  = $this->createMock(RequestHandlerInterface::class);

        $this->shield->method('handle')->willReturn(null);
        $handler->method('handle')->willReturn($response);

        $actual = $this->fixture->process($request, $handler);

        self::assertSame($response, $actual);
    }

    public function testContextMapViaConstructor(): void
    {
        $contextMap = $this->createMock(ContextMapInterface::class);

        $context = $this->createMock(ContextInterface::class);
        $this->shield->method('getContext')->willReturn($context);

        $contextMap->expects(self::once())
            ->method('add')
            ->with($context);

        $this->fixture = new SecurityMiddleware($this->shield, $contextMap);
    }

    /**
     * @param ContextMapInterface|null $map
     *
     * @return ContainerInterface|MockObject
     */
    protected function createContainer(ContextMapInterface $map = null): ContainerInterface
    {
        if (!$map) {
            $map = $this->createMock(ContextMapInterface::class);
        }

        $container = $this->createMock(ContainerInterface::class);

        $container->method('get')->willReturnMap(
            [
                ['security.context', $map],
            ]
        );

        return $container;
    }
}
