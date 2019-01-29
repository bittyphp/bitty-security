<?php

namespace Bitty\Security\Context;

use Psr\Http\Message\ServerRequestInterface;

interface ContextInterface
{
    /**
     * Checks whether or not this should be the default context.
     *
     * @return bool
     */
    public function isDefault(): bool;

    /**
     * Sets context data.
     *
     * @param string $name
     * @param mixed $value
     */
    public function set(string $name, $value): void;

    /**
     * Gets context data.
     *
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     */
    public function get(string $name, $default = null);

    /**
     * Removes context data.
     *
     * @param string $name
     */
    public function remove(string $name): void;

    /**
     * Clears all context data.
     */
    public function clear(): void;

    /**
     * Checks if a request is shielded.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    public function isShielded(ServerRequestInterface $request): bool;

    /**
     * Gets the list of roles required for the request.
     *
     * @param ServerRequestInterface $request
     *
     * @return string[]
     */
    public function getRoles(ServerRequestInterface $request): array;
}
