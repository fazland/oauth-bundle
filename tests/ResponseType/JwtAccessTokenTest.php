<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\ResponseType;

use Fazland\OAuthBundle\Encryption\Jwt;
use Fazland\OAuthBundle\Encryption\KeyPair\KeyPairInterface;
use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use Fazland\OAuthBundle\ResponseType\JwtAccessToken;
use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use Fazland\OAuthBundle\Storage\Jwt as JwtStorage;
use OAuth2\Storage\RefreshTokenInterface;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Symfony\Component\Security\Core\User\UserInterface;

class JwtAccessTokenTest extends TestCase
{
    /**
     * @var UserProviderInterface|ObjectProphecy
     */
    private $userProvider;

    /**
     * @var JwtAccessToken|ObjectProphecy
     */
    private $accessToken;

    /**
     * @var Jwt|ObjectProphecy
     */
    private $encoder;

    /**
     * @var RefreshTokenInterface|ObjectProphecy
     */
    private $refreshStorage;

    /**
     * @var JwtAccessToken
     */
    private $jwt;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->userProvider = $this->prophesize(UserProviderInterface::class);
        $this->accessToken = $this->prophesize(JwtStorage::class);
        $this->encoder = $this->prophesize(Jwt::class);
        $this->refreshStorage = $this->prophesize(RefreshTokenInterface::class);

        $this->jwt = new JwtAccessToken(
            $this->userProvider->reveal(),
            $this->accessToken->reveal(),
            $this->refreshStorage->reveal(),
            ['iss' => 'test'],
            $this->encoder->reveal()
        );
    }

    public function testShouldEncodeAccessTokenWithClientKeyIfNoSubjectIsProvided(): void
    {
        $clientId = 'test_client_id';
        $privateKey = 'TEST PRIVATE KEY';
        $client = $this->prophesize(OAuthClientInterface::class);
        $client->getId()->willReturn($clientId);
        $client->getPrivateKey()->willReturn($privateKey);
        $client->getPublicKey()->willReturn('TEST PUBLIC KEY');
        $client->getSignatureAlgorithm()->willReturn(SignatureAlgorithm::RS256());

        $this->userProvider
            ->provideClient(Argument::withEntry('client_id', 'test_client_id'))
            ->willReturn($client)
        ;

        $token = 'i_am_the_token';
        $this->encoder->encode(Argument::any(), $privateKey, SignatureAlgorithm::RS256)
            ->shouldBeCalled()
            ->willReturn($token)
        ;

        $this->jwt->createAccessToken($clientId, null, null, false);
    }

    public function testShouldEncodeAccessTokenWithUserKeys(): void
    {
        $clientId = 'test_client_id';
        $client = $this->prophesize(OAuthClientInterface::class);
        $client->getId()->willReturn($clientId);
        $client->getPrivateKey()->willReturn('TEST PRIVATE KEY');
        $client->getSignatureAlgorithm()->willReturn(SignatureAlgorithm::RS256());

        $this->userProvider
            ->provideClient(Argument::withEntry('client_id', 'test_client_id'))
            ->willReturn($client)
        ;

        $userId = 42;
        $userPrivateKey = 'TEST USER PRIVATE KEY';
        $user = $this->prophesize(KeyPairInterface::class);
        $user->willImplement(UserInterface::class);
        $user->getPrivateKey()->willReturn($userPrivateKey);
        $user->getSignatureAlgorithm()->willReturn(SignatureAlgorithm::RS512());

        $this->userProvider
            ->provideUser(Argument::withEntry('user_id', $userId))
            ->willReturn($user)
        ;

        $token = 'i_am_the_token';
        $this->encoder->encode(Argument::any(), $userPrivateKey, SignatureAlgorithm::RS512)
            ->shouldBeCalled()
            ->willReturn($token)
        ;

        $this->jwt->createAccessToken($clientId, $userId, null, false);
    }
}
