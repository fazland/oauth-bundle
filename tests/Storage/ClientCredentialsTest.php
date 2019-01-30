<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Storage;

use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Fazland\OAuthBundle\Security\User\OAuthClientInterface;
use Fazland\OAuthBundle\Storage\ClientCredentials;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;

class ClientCredentialsTest extends TestCase
{
    /**
     * @var UserProviderInterface|ObjectProphecy
     */
    private $userProvider;

    /**
     * @var ClientCredentials
     */
    private $storage;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->userProvider = $this->prophesize(UserProviderInterface::class);

        $this->storage = new ClientCredentials($this->userProvider->reveal());
    }

    public function testGetClientDetailsReturnsCorrectInformation(): void
    {
        $client = $this->prophesize(OAuthClientInterface::class);
        $client->getSecret()->willReturn('TEST_SECRET');
        $client->getRedirectUris()->willReturn([]);
        $client->getScope()->willReturn('');

        $clientId = 'TEST';
        $this->userProvider->provideClient(['aud' => $clientId])->willReturn($client);

        $result = $this->storage->getClientDetails($clientId);

        self::assertArrayHasKey('client_id', $result);
        self::assertArrayHasKey('client_secret', $result);
        self::assertArrayHasKey('redirect_uri', $result);
        self::assertArrayHasKey('scope', $result);
    }

    public function testGetClientDetailsReturnsFalseIfNoClientIsFound(): void
    {
        $clientId = 'TEST';
        $this->userProvider->provideClient(['aud' => $clientId])->willReturn(null);

        self::assertFalse($this->storage->getClientDetails($clientId));
    }
}
