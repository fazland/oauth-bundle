<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Firewall;

use Fazland\OAuthBundle\Security\Firewall\OAuthFirewall;
use OAuth2\HttpFoundationBridge\Request;
use OAuth2\Response;
use OAuth2\Server;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request as HttpRequest;
use Symfony\Component\HttpFoundation\Response as HttpResponse;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class OAuthFirewallTest extends TestCase
{
    /**
     * @var Server|ObjectProphecy
     */
    private $server;

    /**
     * @var TokenStorageInterface|ObjectProphecy
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface|ObjectProphecy
     */
    private $authenticationManager;

    /**
     * @var OAuthFirewall
     */
    private $firewall;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        $this->server = $this->prophesize(Server::class);
        $this->tokenStorage = $this->prophesize(TokenStorageInterface::class);
        $this->authenticationManager = $this->prophesize(AuthenticationManagerInterface::class);

        $this->firewall = new OAuthFirewall(
            $this->server->reveal(),
            $this->tokenStorage->reveal(),
            $this->authenticationManager->reveal()
        );
    }

    public function provideAuthorizationHeader(): iterable
    {
        yield [null];
        yield ['I am not a bearer authorization header'];
    }

    /**
     * @dataProvider provideAuthorizationHeader
     */
    public function testHandleShouldNotActIfNoAuthorizationHeaderIsPresentNorIsBearer(?string $header): void
    {
        $headers = $this->prophesize(HeaderBag::class);
        $headers->get('Authorization')->willReturn($header);

        $request = $this->prophesize(HttpRequest::class);
        $request->headers = $headers;

        $this->server->getAccessTokenData(Argument::cetera())->shouldNotBeCalled();
        $this->authenticationManager->authenticate(Argument::any())->shouldNotBeCalled();

        $event = $this->prophesize(GetResponseEvent::class);
        $event->getRequest()->willReturn($request);
        $event->setResponse(Argument::any())->shouldNotBeCalled();

        $this->firewall->handle($event->reveal());
    }

    public function testHandleShouldReturnUnauthorizedResponseIfServerHasEmptyTokenDataForCurrentRequest(): void
    {
        $httpRequest = new HttpRequest();
        $httpRequest->headers->set('Authorization', 'Bearer with_token');

        $request = Request::createFromRequest($httpRequest);
        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $event = $this->prophesize(GetResponseEvent::class);
        $event->getRequest()->willReturn($httpRequest);
        $event
            ->setResponse(
                JsonResponse::create($response->getParameters(), $response->getStatusCode(), $response->getHttpHeaders())
            )
            ->shouldBeCalled()
        ;

        $this->server->getAccessTokenData($request, $response)->willReturn([]);

        $this->firewall->handle($event->reveal());
    }
}
