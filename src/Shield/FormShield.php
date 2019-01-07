<?php

namespace Bitty\Security\Shield;

use Bitty\Http\RedirectResponse;
use Bitty\Http\Response;
use Bitty\Security\Shield\AbstractShield;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class FormShield extends AbstractShield
{
    /**
     * {@inheritDoc}
     */
    public function handle(ServerRequestInterface $request): ?ResponseInterface
    {
        $path = $request->getUri()->getPath();

        if ($path === $this->config['login.path']) {
            return $this->handleFormLogin($request);
        }

        if ($path === $this->config['logout.path']) {
            $user = $this->context->get('user');

            $this->context->clear();
            $this->triggerEvent('security.logout', $user);

            return new RedirectResponse($this->config['logout.target']);
        }

        $match = $this->context->getPatternMatch($request);
        if (empty($match) || empty($match['roles'])) {
            return null;
        }

        $user = $this->context->get('user');
        if ($user) {
            $user = $this->authenticator->reloadUser($user);
        }

        if (!$user) {
            $this->context->set('login.target', $path);

            return new RedirectResponse($this->config['login.path']);
        }

        $this->authorize($user, $match['roles']);

        return null;
    }

    /**
     * Handles form logins.
     *
     * @param ServerRequestInterface $request
     *
     * @return ResponseInterface|null
     */
    protected function handleFormLogin(ServerRequestInterface $request): ?ResponseInterface
    {
        if ('POST' !== $request->getMethod()) {
            return null;
        }

        $params = $request->getParsedBody();
        if (!is_array($params)) {
            return null;
        }

        $usernameField = $this->config['login.username'];
        $passwordField = $this->config['login.password'];

        $username = empty($params[$usernameField]) ? '' : $params[$usernameField];
        $password = empty($params[$passwordField]) ? '' : $params[$passwordField];

        if (empty($username) || empty($password)) {
            return null;
        }

        $user = $this->authenticate($username, $password);

        $target = $this->config['login.target'];
        if ($this->config['login.use_referrer']) {
            $target = $this->context->get('login.target', $target);
            $this->context->remove('login.target');
        }

        return new RedirectResponse($target);
    }

    /**
     * {@inheritDoc}
     */
    protected function getDefaultConfig(): array
    {
        return [
            'login.path' => '/login',
            'login.target' => '/',
            'login.username' => 'username',
            'login.password' => 'password',
            'login.use_referrer' => true,
            'logout.path' => '/logout',
            'logout.target' => '/',
        ];
    }
}
