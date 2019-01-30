<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Exception;

use OAuth2\Response as OAuthResponse;
use Symfony\Component\HttpFoundation\JsonResponse;

class OAuthAuthenticationException extends \RuntimeException
{
    /**
     * @var JsonResponse
     */
    private $response;

    /**
     * {@inheritdoc}
     */
    public function __construct(int $statusCode, string $error, string $errorDescription, $code = 0, ?\Throwable $previous = null)
    {
        $response = new OAuthResponse();
        $response->setError($statusCode, $error, $errorDescription);

        $this->response = JsonResponse::create($response->getParameters(), $response->getStatusCode(), $response->getHttpHeaders());

        parent::__construct($errorDescription, $code, $previous);
    }

    /**
     * @return JsonResponse
     */
    public function getHttpResponse(): JsonResponse
    {
        return $this->response;
    }
}
