<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Controller;

use OAuth2\HttpFoundationBridge\Request as OAuthRequest;
use OAuth2\Response as OAuthResponse;
use OAuth2\Server;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TokenController extends AbstractController
{
    /**
     * Entry point for OAuth2 token requests.
     * Accept a well-formed OAuth2 token request as per RFC 6749 and
     * subsequent updates.
     * As requested by the spec, the response is _always_ json-encoded
     * and the HTTP status code is set accordingly to the response.
     *
     * Returns:
     * 200 - If token request succeeded. The body contains the newly generated token and its validity.
     * 400 - If request contains unsupported parameters, grant type is invalid or every other error.
     * 401 - If credentials are invalid.
     *
     * @param Request $request
     * @param Server  $server
     *
     * @return Response
     */
    public function tokenAction(Request $request, Server $server): Response
    {
        $oauthResponse = new OAuthResponse();

        if (Request::METHOD_GET === $request->getMethod()) {
            $request = $request->duplicate();
            $request->setMethod(Request::METHOD_POST);
            $request->request->add($request->query->all());
        } elseif (\preg_match('/application\/json/', $request->headers->get('Content-Type'))) {
            $content = $request->getContent();
            if ('' !== $content) {
                $request->request->add(\json_decode($request->getContent(), true));
            }
        }

        $server->getTokenController()
            ->handleTokenRequest(OAuthRequest::createFromRequest($request), $oauthResponse)
        ;

        return JsonResponse::create($oauthResponse->getParameters(), $oauthResponse->getStatusCode(), $oauthResponse->getHttpHeaders());
    }

    /**
     * Needed for CORS requests.
     * Shows which methods are allowed (OPTIONS, GET and POST).
     *
     * Returns:
     * 200 - OK
     *
     * @param Request $request
     *
     * @return Response
     * @ignore
     */
    public function optionsAction(Request $request): Response
    {
        $allowedMethods = \implode(', ', [Request::METHOD_GET, Request::METHOD_POST, Request::METHOD_OPTIONS]);
        $headers = [
            'Allow' => $allowedMethods,
            'Access-Control-Allow-Methods' => $allowedMethods,
            'Access-Control-Allow-Credentials' => 'true',
            'Access-Control-Expose-Headers' => 'Authorization, Content-Length',
        ];

        if ($request->headers->has('Access-Control-Request-Headers')) {
            $headers['Access-Control-Allow-Headers'] = $request->headers->get('Access-Control-Request-Headers');
        }

        return Response::create(null, Response::HTTP_OK, $headers);
    }
}
