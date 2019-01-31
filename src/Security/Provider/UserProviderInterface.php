<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Provider;

use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface UserProviderInterface
{
    /**
     * Provides a {@see UserInterface} retrieved from the token data.
     *
     * @param array $tokenData
     *
     * @return UserInterface|null
     */
    public function provideUser(array $tokenData): ?UserInterface;

    /**
     * Provides a {@see OAuthClientInterface} retrieved from the token data.
     *
     * @param array $tokenData
     *
     * @return OAuthClientInterface|null
     */
    public function provideClient(array $tokenData): ?OAuthClientInterface;

    /**
     * Creates and stores a new {@see OAuthClientInterface}.
     *
     * @param string $name
     * @param array  $redirectUris
     * @param array  $grantTypes
     *
     * @return OAuthClientInterface
     */
    public function createClient(string $name, array $redirectUris, array $grantTypes): OAuthClientInterface;
}
