<?php

namespace Bitty\Tests\Security\Shield;

use Bitty\Container\ContainerAwareInterface;
use Bitty\Security\Authentication\AuthenticatorInterface;
use Bitty\Security\Authorization\AuthorizerInterface;
use Bitty\Security\Context\ContextInterface;
use Bitty\Security\Shield\AbstractShield;
use Bitty\Security\Shield\ShieldInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AbstractShieldTest extends TestCase
{
    /**
     * @var AbstractShield|MockObject
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

        $this->fixture = $this->getMockForAbstractClass(
            AbstractShield::class,
            [$this->context, $this->authenticator, $this->authorizer]
        );
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(ShieldInterface::class, $this->fixture);
        self::assertInstanceOf(ContainerAwareInterface::class, $this->fixture);
    }

    public function testGetContext(): void
    {
        $actual = $this->fixture->getContext();

        self::assertSame($this->context, $actual);
    }

    public function testGetDefaultConfig(): void
    {
        $actual = $this->fixture->getDefaultConfig();

        self::assertEquals([], $actual);
    }
}
