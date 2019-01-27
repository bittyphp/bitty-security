<?php

namespace Bitty\Security\Context;

use Bitty\Http\Session\SessionInterface;
use Bitty\Security\Context\ContextInterface;
use Psr\Http\Message\ServerRequestInterface;

class SessionContext implements ContextInterface
{
    /**
     * @var SessionInterface
     */
    protected $session = null;

    /**
     * @var string
     */
    protected $name = null;

    /**
     * @var array[]
     */
    protected $paths = null;

    /**
     * @var mixed[]
     */
    protected $config = null;

    /**
     * @param SessionInterface $session
     * @param string $name
     * @param array[] $paths Formatted as [pattern => [role, ...]]
     * @param mixed[] $config
     */
    public function __construct(
        SessionInterface $session,
        string $name,
        array $paths,
        array $config = []
    ) {
        $this->session = $session;
        $this->name    = $name;
        $this->paths   = $paths;
        $this->config  = array_merge($this->getDefaultConfig(), $config);
    }

    /**
     * {@inheritDoc}
     */
    public function isDefault(): bool
    {
        return (bool) $this->config['default'];
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $name, $value): void
    {
        if ('user' === $name) {
            $now = time();
            $this->set('destroy', $now + $this->config['destroy.delay']);
            $this->session->regenerate();
            $this->remove('destroy');
            $this->set('login', $now);
            $this->set('active', $now);
            $this->set('expires', $now + $this->config['ttl']);
        }

        $this->session->set($this->name.'/'.$name, $value);
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $name, $default = null)
    {
        if ('user' === $name) {
            $now     = time();
            $expires = $this->get('expires', 0);
            $destroy = $this->get('destroy', INF);
            $active  = $this->get('active', 0) + ($this->config['timeout'] ?: INF);
            $clear   = min($expires, $destroy, $active);

            if ($now > $clear) {
                // This session should be destroyed.
                // Clear out all data to prevent unauthorized use.
                $this->clear();
            } else {
                // Update last active time.
                $this->set('active', $now);
            }
        }

        return $this->session->get($this->name.'/'.$name, $default);
    }

    /**
     * {@inheritDoc}
     */
    public function remove(string $name): void
    {
        $this->session->remove($this->name.'/'.$name);
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): void
    {
        foreach ($this->session->all() as $key => $value) {
            if (substr($key, 0, strlen($this->name.'/')) === $this->name.'/') {
                $this->session->remove($key);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isShielded(ServerRequestInterface $request): bool
    {
        $match = $this->getPatternMatch($request);

        return !empty($match) && !empty($match['roles']);
    }

    /**
     * {@inheritDoc}
     */
    public function getPatternMatch(ServerRequestInterface $request): array
    {
        $path = $request->getUri()->getPath();
        foreach ($this->paths as $pattern => $roles) {
            if (preg_match("`$pattern`", $path)) {
                return [
                    'shield' => $this->name,
                    'pattern' => $pattern,
                    'roles' => $roles,
                ];
            }
        }

        return [];
    }

    /**
     * Gets the default configuration settings.
     *
     * @return mixed[]
     */
    protected function getDefaultConfig(): array
    {
        return [
            // Whether or not this is the default context.
            'default' => true,

            // How long (in seconds) sessions are good for.
            // Defaults to 24 hours.
            'ttl' => 86400,

            // Timeout (in seconds) to invalidate a session after no activity.
            // Defaults to zero (disabled).
            'timeout' => 0,

            // Delay (in seconds) to wait before destroying an old session.
            // Sessions are flagged as "destroyed" during re-authentication.
            // Allows for a network lag in asynchronous applications.
            'destroy.delay' => 30,
        ];
    }
}
