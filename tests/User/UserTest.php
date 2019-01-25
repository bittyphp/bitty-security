<?php

namespace Bitty\Tests\Security\User;

use Bitty\Security\User\User;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase
{
    public function testInstanceOf(): void
    {
        $fixture = new User(uniqid(), uniqid());

        self::assertInstanceOf(UserInterface::class, $fixture);
    }

    public function testGetUsername(): void
    {
        $username = uniqid();

        $fixture = new User($username, uniqid());

        $actual = $fixture->getUsername();

        self::assertEquals($username, $actual);
    }

    public function testGetPassword(): void
    {
        $password = uniqid();

        $fixture = new User(uniqid(), $password);

        $actual = $fixture->getPassword();

        self::assertEquals($password, $actual);
    }

    public function testGetSalt(): void
    {
        $salt = uniqid();

        $fixture = new User(uniqid(), uniqid(), $salt);

        $actual = $fixture->getSalt();

        self::assertEquals($salt, $actual);
    }

    public function testGetNullSalt(): void
    {
        $fixture = new User(uniqid(), uniqid());

        $actual = $fixture->getSalt();

        self::assertNull($actual);
    }

    public function testGetRoles(): void
    {
        $roles = [uniqid(), uniqid()];

        $fixture = new User(uniqid(), uniqid(), null, $roles);

        $actual = $fixture->getRoles();

        self::assertEquals($roles, $actual);
    }

    public function testGetEmptyRoles(): void
    {
        $fixture = new User(uniqid(), uniqid());

        $actual = $fixture->getRoles();

        self::assertEquals([], $actual);
    }

    public function testSleep(): void
    {
        $fixture = new User(uniqid(), uniqid());

        $actual = $fixture->__sleep();

        self::assertEquals(['username', 'password', 'salt', 'roles'], $actual);
    }
}
