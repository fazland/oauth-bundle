<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\ResponseType;

use Cake\Chronos\Chronos;
use Fazland\OAuthBundle\Encryption\KeyPair\KeyPairInterface;
use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\ResponseType\JwtAccessToken as BaseJwtAccessToken;
use OAuth2\Storage\AccessTokenInterface as AccessTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;

class JwtAccessToken extends BaseJwtAccessToken
{
    public const DEFAULT_REFRESH_TOKEN_LIFETIME = 2592000; // 30 days
    public const DEFAULT_ACCESS_LIFETIME = 3600;           // 1 hour

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * {@inheritdoc}
     */
    public function __construct(
        UserProviderInterface $userProvider,
        ?AccessTokenStorageInterface $tokenStorage = null,
        ?RefreshTokenInterface $refreshStorage = null,
        array $config = [],
        ?EncryptionInterface $encryptionUtil = null
    ) {
        $this->userProvider = $userProvider;

        $config = [
            'issuer' => $config['iss'],
            'store_encrypted_token_string' => false,
            'refresh_token_lifetime' => $config['refresh_token_lifetime'] ?? self::DEFAULT_REFRESH_TOKEN_LIFETIME,
            'access_lifetime' => $config['access_lifetime'] ?? self::DEFAULT_ACCESS_LIFETIME,
        ];

        parent::__construct(null, $tokenStorage, $refreshStorage, $config, $encryptionUtil);
    }

    /**
     * {@inheritdoc}
     */
    public function createAccessToken($clientId, $userId, $scope = null, $includeRefreshToken = true): array
    {
        if (\is_callable($this->config['access_lifetime'])) {
            $accessLifetime = $this->config['access_lifetime']($clientId, $userId, $scope) ?? self::DEFAULT_ACCESS_LIFETIME;
        } else {
            $accessLifetime = (int) $this->config['access_lifetime'];
        }

        $payload = $this->generatePayload($clientId, $userId, $accessLifetime, $scope);
        $accessToken = $this->encodeToken($payload, $clientId);

        $now = Chronos::now()->getTimestamp();

        /*
         * Save the token to a secondary storage.  This is implemented on the
         * OAuth2\Storage\JwtAccessToken side, and will not actually store anything,
         * if no secondary storage has been supplied
         */
        $tokenToStore = $this->config['store_encrypted_token_string'] ? $accessToken : $payload['id'];
        if (null !== $this->tokenStorage) {
            $this->tokenStorage->setAccessToken($tokenToStore, $clientId, $userId, $accessLifetime ? $now + $accessLifetime : null, $scope);
        }

        // token to return to the client
        $token = [
            'access_token' => $accessToken,
            'expires_in' => $accessLifetime,
            'token_type' => $this->config['token_type'],
            'scope' => $scope,
        ];

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2\Storage\RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && null !== $this->refreshStorage) {
            $refreshToken = $this->generateRefreshToken();

            if (\is_callable($this->config['refresh_token_lifetime'])) {
                $refreshTokenLifetime = $this->config['refresh_token_lifetime']($clientId, $userId, $scope) ?? self::DEFAULT_REFRESH_TOKEN_LIFETIME;
            } else {
                $refreshTokenLifetime = (int) $this->config['refresh_token_lifetime'];
            }

            $expires = 0;

            if ($refreshTokenLifetime > 0) {
                $expires = $now + $refreshTokenLifetime;
            }

            $this->refreshStorage->setRefreshToken($refreshToken, $clientId, $userId, $expires, $scope);
            $token['refresh_token'] = $refreshToken;
        }

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function encodeToken(array $token, $clientId = null): string
    {
        /** @var KeyPairInterface $client */
        $client = $this->getKeyPair($token);

        return $this->encryptionUtil->encode($token, $client->getPrivateKey(), (string) $client->getSignatureAlgorithm());
    }

    /**
     * This function can be used to create custom JWT payloads.
     *
     * @param mixed       $clientId - Client identifier related to the access token
     * @param mixed       $userId   - User ID associated with the access token
     * @param int         $lifetime - Scopes to be stored in space-separated string
     * @param string|null $scope
     *
     * @return array
     */
    private function generatePayload($clientId, $userId, int $lifetime, ?string $scope): array
    {
        $now = Chronos::now()->getTimestamp();
        $expires = $now + $lifetime;

        $id = $this->generateAccessToken();

        return [
            'id' => $id, // for BC (see #591)
            'jti' => $id,
            'iss' => $this->config['issuer'],
            'aud' => $clientId,
            'sub' => $userId,
            'exp' => $expires,
            'iat' => $now,
            'token_type' => $this->config['token_type'],
            'scope' => $scope,
        ];
    }

    protected function getKeyPair(array $token): KeyPairInterface
    {
        $client = $this->userProvider->provideClient($token);

        $subject = $token['sub'];
        if (null === $subject) {
            return $client;
        }

        $user = $this->userProvider->provideUser($token);
        return $user instanceof KeyPairInterface ? $user : $client;
    }
}
