<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Firewall;

use Fazland\OAuthBundle\Security\Authentication\Token\OAuthToken;
use OAuth2\HttpFoundationBridge\Request;
use OAuth2\Response;
use OAuth2\Server;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response as HttpResponse;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class OAuthFirewall implements ListenerInterface
{
    /**
     * @var Server
     */
    private $oauthServer;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    public function __construct(
        Server $oauthServer,
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager
    ) {
        $this->oauthServer = $oauthServer;
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event): void
    {
        $request = $event->getRequest();
        $authHeader = $request->headers->get('Authorization');
        if (null === $authHeader || ! \preg_match('/^bearer /i', $authHeader)) {
            return;
        }

        $request = Request::createFromRequest($event->getRequest());

        $response = new Response();
        $response->setError(HttpResponse::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        $data = $this->oauthServer->getAccessTokenData($request, $response);

        if (empty($data)) {
            $event->setResponse(JsonResponse::create($response->getParameters(), $response->getStatusCode(), $response->getHttpHeaders()));

            return;
        }

        $token = new OAuthToken();
        $token->setToken($data);

        try {
            $ret = $this->authenticationManager->authenticate($token);

            if ($ret instanceof TokenInterface) {
                $this->tokenStorage->setToken($ret);
            }

            if ($ret instanceof HttpResponse) {
                $event->setResponse($ret);
            }
        } catch (AuthenticationException $ex) {
            $previous = $ex->getPrevious();
            if (null !== $previous) {
                $event->setResponse($previous->getHttpResponse());
            }
        }
    }
}
