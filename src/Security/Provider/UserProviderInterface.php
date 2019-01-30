<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Provider;

use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface UserProviderInterface
{
    /**
     * Provides a User retrieved from the token data.
     *
     * @param array $tokenData
     *
     * @return UserInterface|null
     */
    public function provideUser(array $tokenData): ?UserInterface;

    /**
     * Provides a OAuthClientInterface retrieved from the token data.
     *
     * @param array $tokenData
     *
     * @return OAuthClientInterface|null
     */
    public function provideClient(array $tokenData): ?OAuthClientInterface;
}
