<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Firewall;

use Fazland\OAuthBundle\Exception\OAuthAuthenticationException;
use Fazland\OAuthBundle\Security\Firewall\OAuthFirewall;
use Fazland\OAuthBundle\Security\Token\OAuthToken;
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
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

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

        $event = $this->prophesize(RequestEvent::class);
        $event->getRequest()->willReturn($request);
        $event->setResponse(Argument::any())->shouldNotBeCalled();

        ($this->firewall)($event->reveal());
    }

    public function testHandleShouldReturnUnauthorizedResponseIfServerHasEmptyTokenDataForCurrentRequest(): void
    {
        $httpRequest = new HttpRequest();
        $httpRequest->headers->set('Authorization', 'Bearer with_token');

        $request = Request::createFromRequest($httpRequest);
        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $event = $this->prophesize(RequestEvent::class);
        $event->getRequest()->willReturn($httpRequest);
        $event
            ->setResponse(Argument::that(function (HttpResponse $r) use ($response): bool {
                self::assertEquals(\json_decode($r->getContent(), true), $response->getParameters());
                self::assertEquals($r->getStatusCode(), $response->getStatusCode());

                return true;
            }))
            ->shouldBeCalled()
        ;

        $this->server->getAccessTokenData($request, $response)->willReturn([]);

        ($this->firewall)($event->reveal());
    }

    public function testHandleShouldNotActIfAuthenticateThrowsWithoutOAuthAuthenticationException(): void
    {
        $httpRequest = new HttpRequest();
        $httpRequest->headers->set('Authorization', 'Bearer with_token');

        $request = Request::createFromRequest($httpRequest);
        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $this->server->getAccessTokenData($request, $response)->willReturn(['I am not an empty token data']);

        $exception = new AuthenticationException();

        $event = $this->prophesize(RequestEvent::class);
        $event->getRequest()->willReturn($httpRequest);
        $event->setResponse(Argument::any())
            ->shouldNotBeCalled()
        ;

        $this->authenticationManager->authenticate(Argument::type(OAuthToken::class))
            ->willThrow($exception)
        ;

        ($this->firewall)($event->reveal());
    }

    public function testHandleShouldReturnExceptionResponseIfAuthenticateThrowsWithOAuthAuthenticationException(): void
    {
        $httpRequest = new HttpRequest();
        $httpRequest->headers->set('Authorization', 'Bearer with_token');

        $request = Request::createFromRequest($httpRequest);
        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $this->server->getAccessTokenData($request, $response)->willReturn(['I am not an empty token data']);

        $exceptionResponse = $this->prophesize(JsonResponse::class);
        $oauthException = $this->prophesize(OAuthAuthenticationException::class);
        $oauthException->getHttpResponse()->willReturn($exceptionResponse);

        $exception = new AuthenticationException('OAuth2 authentication failed', 0, $oauthException->reveal());

        $event = $this->prophesize(RequestEvent::class);
        $event->getRequest()->willReturn($httpRequest);
        $event->setResponse($exceptionResponse)
            ->shouldBeCalled()
        ;

        $this->authenticationManager->authenticate(Argument::type(OAuthToken::class))
            ->willThrow($exception)
        ;

        ($this->firewall)($event->reveal());
    }

    public function testHandleShouldSetTheTokenIfAuthenticateReturnsTheToken(): void
    {
        $httpRequest = new HttpRequest();
        $httpRequest->headers->set('Authorization', 'Bearer with_token');

        $request = Request::createFromRequest($httpRequest);
        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $this->server->getAccessTokenData($request, $response)->willReturn(['I am not an empty token data']);

        $exceptionResponse = $this->prophesize(JsonResponse::class);
        $oauthException = $this->prophesize(OAuthAuthenticationException::class);
        $oauthException->getHttpResponse()->willReturn($exceptionResponse);

        $event = $this->prophesize(RequestEvent::class);
        $event->getRequest()->willReturn($httpRequest);
        $event->setResponse(Argument::any())
            ->shouldNotBeCalled()
        ;

        $token = $this->prophesize(TokenInterface::class);

        $this->authenticationManager->authenticate(Argument::type(OAuthToken::class))
            ->willReturn($token)
        ;

        $this->tokenStorage->setToken($token)
            ->shouldBeCalled()
        ;

        ($this->firewall)($event->reveal());
    }
}
