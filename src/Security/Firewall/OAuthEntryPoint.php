<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Firewall;

use OAuth2\Response as OAuthResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class OAuthEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * {@inheritdoc}
     */
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $response = new OAuthResponse();
        $response->setError(Response::HTTP_UNAUTHORIZED, 'access_denied', 'OAuth authentication required');

        return JsonResponse::create($response->getParameters(), $response->getStatusCode(), $response->getHttpHeaders());
    }
}
