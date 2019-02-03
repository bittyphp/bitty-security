<?php

namespace Bitty\Tests\Security\Context;

use Bitty\Security\Context\ContextMap;
use Bitty\Security\Context\ContextMapInterface;
use Bitty\Security\Context\ContextMapServiceProvider;
use Interop\Container\ServiceProviderInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

class ContextMapServiceProviderTest extends TestCase
{
    /**
     * @var ContextMapServiceProvider
     */
    private $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new ContextMapServiceProvider();
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ServiceProviderInterface::class, $this->fixture);
    }

    public function testGetFactories(): void
    {
        $actual = $this->fixture->getFactories();

        self::assertEquals([], $actual);
    }

    public function testGetExtensions(): void
    {
        $actual = $this->fixture->getExtensions();

        self::assertContainsOnlyInstancesOf(\Closure::class, $actual);
        self::assertArrayHasKey('security.context', $actual);
    }

    public function testContextWithPrevious(): void
    {
        $container  = $this->createMock(ContainerInterface::class);
        $contextMap = $this->createMock(ContextMapInterface::class);

        $extensions = $this->fixture->getExtensions();

        $actual = $extensions['security.context']($container, $contextMap);

        self::assertSame($contextMap, $actual);
    }

    public function testContextWithoutPrevious(): void
    {
        $container = $this->createMock(ContainerInterface::class);

        $extensions = $this->fixture->getExtensions();

        $actual = $extensions['security.context']($container);

        self::assertInstanceOf(ContextMap::class, $actual);
    }
}
