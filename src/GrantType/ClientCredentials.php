<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\GrantType;

use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\ResponseType\AccessTokenInterface;

class ClientCredentials extends HttpBasic implements GrantTypeInterface
{
    public const NAME = 'client_credentials';

    /**
     * @var array|null
     */
    private $clientData;

    public function getClientId()
    {
        return @parent::getClientId();
    }

    /**
     * {@inheritdoc}
     */
    public function getQueryStringIdentifier(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function getScope(): ?string
    {
        $this->loadClientData();

        return $this->clientData['scope'] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserId()
    {
        $this->loadClientData();

        return $this->clientData['user_id'] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope): array
    {
        /**
         * Client Credentials Grant does NOT include a refresh token.
         *
         * @see http://tools.ietf.org/html/rfc6749#section-4.4.3
         */
        $includeRefreshToken = false;

        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
    }

    /**
     * Ensure the client data has been loaded from the storage.
     */
    private function loadClientData(): void
    {
        if (null !== $this->clientData) {
            return;
        }

        $this->clientData = $this->storage->getClientDetails($this->getClientId());
    }
}
