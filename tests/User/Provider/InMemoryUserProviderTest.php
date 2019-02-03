<?php

namespace Bitty\Tests\Security\User\Provider;

use Bitty\Security\Exception\AuthenticationException;
use Bitty\Security\User\Provider\AbstractUserProvider;
use Bitty\Security\User\Provider\InMemoryUserProvider;
use Bitty\Security\User\UserInterface;
use PHPUnit\Framework\TestCase;

class InMemoryUserProviderTest extends TestCase
{
    /**
     * @var InMemoryUserProvider
     */
    private $fixture = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = new InMemoryUserProvider([]);
    }

    public function testInstanceOf(): void
    {
        self::assertInstanceOf(AbstractUserProvider::class, $this->fixture);
    }

    public function testGetUserBlocksLongPasswords(): void
    {
        $username = str_repeat('*', AbstractUserProvider::MAX_USERNAME_LEN + 1);

        self::expectException(AuthenticationException::class);
        self::expectExceptionMessage('Invalid username.');

        $this->fixture->getUser($username);
    }

    public function testGetUserNotSet(): void
    {
        $actual = $this->fixture->getUser(uniqid());

        self::assertNull($actual);
    }

    public function testGetUserNoPasswordSet(): void
    {
        $user = uniqid();

        $this->fixture = new InMemoryUserProvider([$user => ['salt' => uniqid()]]);

        $actual = $this->fixture->getUser($user);

        self::assertNull($actual);
    }

    /**
     * @param array $users
     * @param string $username
     * @param array $expected
     *
     * @dataProvider sampleUsers
     */
    public function testGetUser(array $users, string $username, array $expected): void
    {
        $this->fixture = new InMemoryUserProvider($users);

        $user = $this->fixture->getUser($username);

        self::assertInstanceOf(UserInterface::class, $user);

        $actual = [
            'username' => $user->getUsername(),
            'password' => $user->getPassword(),
            'salt' => $user->getSalt(),
            'roles' => $user->getRoles(),
        ];

        self::assertEquals($expected, $actual);
    }

    public function sampleUsers(): array
    {
        $username = uniqid();
        $password = uniqid();
        $salt     = uniqid();
        $roleA    = uniqid();
        $roleB    = uniqid();
        $roles    = [$roleA, $roleB];
        $userA    = [
            'password' => uniqid(),
            'salt' => uniqid(),
            'roles' => [uniqid()],
        ];
        $userB    = [
            'password' => uniqid(),
            'salt' => uniqid(),
            'roles' => [uniqid()],
        ];

        return [
            'no salt' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'roles' => $roles,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => null,
                    'roles' => $roles,
                ],
            ],
            'null salt' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => null,
                        'roles' => $roles,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => null,
                    'roles' => $roles,
                ],
            ],
            'empty salt' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => '',
                        'roles' => $roles,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => null,
                    'roles' => $roles,
                ],
            ],
            'no roles' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => $salt,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => $salt,
                    'roles' => [],
                ],
            ],
            'null roles' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => $salt,
                        'roles' => null,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => $salt,
                    'roles' => [],
                ],
            ],
            'empty roles' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => $salt,
                        'roles' => [],
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => $salt,
                    'roles' => [],
                ],
            ],
            'with salt and roles' => [
                'users' => [
                    uniqid() => $userA,
                    $username => [
                        'password' => $password,
                        'salt' => $salt,
                        'roles' => $roles,
                    ],
                    uniqid() => $userB,
                ],
                'user' => $username,
                'expected' => [
                    'username' => $username,
                    'password' => $password,
                    'salt' => $salt,
                    'roles' => $roles,
                ],
            ],
        ];
    }
}
