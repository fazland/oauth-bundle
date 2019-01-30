<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\OAuth\GrantType;

use Fazland\OAuthBundle\GrantType\ClientCredentials;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;

class ClientCredentialsTest extends TestCase
{
    /**
     * @var ClientCredentialsInterface|ObjectProphecy
     */
    private $storage;

    /**
     * @var ClientCredentials
     */
    private $grantType;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->storage = $this->prophesize(ClientCredentialsInterface::class);

        $this->grantType = new ClientCredentials($this->storage->reveal());
    }

    public function testGetQueryStringIdentifier(): void
    {
        self::assertEquals(ClientCredentials::NAME, $this->grantType->getQueryStringIdentifier());
    }

    public function testGetScopeShouldReturnNullIfNotSet(): void
    {
        $this->storage->getClientDetails(Argument::any())->willReturn([]);

        self::assertNull($this->grantType->getScope());
    }

    public function testGetScopeShouldWork(): void
    {
        $scope = 'the_scope';
        $this->storage->getClientDetails(Argument::any())->willReturn(['scope' => $scope]);

        self::assertEquals($scope, $this->grantType->getScope());
    }

    public function testGetUserIdShouldReturnNullIfNotSet(): void
    {
        $this->storage->getClientDetails(Argument::any())->willReturn([]);

        self::assertNull($this->grantType->getUserId());
    }

    public function testGetUserShouldWork(): void
    {
        $userId = 42;
        $this->storage->getClientDetails(Argument::any())->willReturn(['user_id' => $userId]);

        self::assertEquals($userId, $this->grantType->getUserId());
    }

    public function testCreateAccessTokenShouldCreateTokenWithoutRefreshToken(): void
    {
        $clientId = 'the_client_id';
        $userId = 42;
        $scope = 'the_scope';
        $includeRefreshToken = false;

        $token = ['i_am_the_token'];
        $accessToken = $this->prophesize(AccessTokenInterface::class);
        $accessToken->createAccessToken($clientId, $userId, $scope, $includeRefreshToken)
            ->shouldBeCalled()
            ->willReturn($token)
        ;

        self::assertEquals($token, $this->grantType->createAccessToken($accessToken->reveal(), $clientId, $userId, $scope));
    }
}
