<?php

namespace Bitty\Tests\Security\User\Provider;

use Bitty\Security\User\Provider\AbstractUserProvider;
use Bitty\Security\User\Provider\UserProviderInterface;
use PHPUnit\Framework\TestCase;

class AbstractUserProviderTest extends TestCase
{
    public function testInstanceOf(): void
    {
        $fixture = $this->getMockForAbstractClass(AbstractUserProvider::class);

        self::assertInstanceOf(UserProviderInterface::class, $fixture);
    }
}
