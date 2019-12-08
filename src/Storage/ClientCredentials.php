<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Storage;

use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use OAuth2\Storage\ClientCredentialsInterface;

class ClientCredentials implements ClientCredentialsInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientCredentials($clientId, $clientSecret = null): bool
    {
        $client = $this->provideClient($clientId);

        return null !== $client && $client->getSecret() === $clientSecret;
    }

    /**
     * {@inheritdoc}
     */
    public function isPublicClient($clientId): bool
    {
        $client = $this->provideClient($clientId);
        $secret = null !== $client ? $client->getSecret() : null;

        return null === $secret || '' === $secret;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientDetails($clientId)
    {
        $client = $this->provideClient($clientId);
        if (null === $client) {
            return false;
        }

        return [
            'client_id' => $clientId,
            'client_secret' => $client->getSecret(),
            'redirect_uri' => \implode(' ', $client->getRedirectUris()),
            'scope' => $client->getScope(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getClientScope($clientId): string
    {
        $client = $this->provideClient($clientId);

        return null !== $client ? $client->getScope() : '';
    }

    /**
     * {@inheritdoc}
     */
    public function checkRestrictedGrantType($clientId, $grantType): bool
    {
        $client = $this->provideClient($clientId);

        return null !== $client && \in_array($grantType, $client->getGrantTypes(), true);
    }

    private function provideClient(?string $clientId): ?OAuthClientInterface
    {
        if (null === $clientId) {
            return null;
        }

        return $this->userProvider->provideClient(['client_id' => $clientId]);
    }
}
