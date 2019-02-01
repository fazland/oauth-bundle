<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Controller;

use Fazland\OAuthBundle\Tests\Fixtures\Token\AppKernel;
use Fazland\OAuthBundle\Tests\Fixtures\Token\OAuthClient;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * @group functional
 */
class TokenControllerTest extends WebTestCase
{
    public function testTokenOptionsAction(): void
    {
        $response = $this->request('/token', Request::METHOD_OPTIONS);
        $expectedAllowedMethods = \implode(', ', [Request::METHOD_GET, Request::METHOD_POST, Request::METHOD_OPTIONS]);

        self::assertEquals(Response::HTTP_OK, $response->getStatusCode());
        self::assertEmpty($response->getContent());
        self::assertEquals($expectedAllowedMethods, $response->headers->get('Allow'));
        self::assertEquals($expectedAllowedMethods, $response->headers->get('Access-Control-Allow-Methods'));
        self::assertEquals('true', $response->headers->get('Access-Control-Allow-Credentials'));
        self::assertEquals('Authorization, Content-Length', $response->headers->get('Access-Control-Expose-Headers'));
        self::assertFalse($response->headers->has('Access-Control-Allow-Headers'));
    }

    public function testTokenOptionsActionShouldAlsoSetAccessControlAllowHeaders(): void
    {
        $response = $this->request('/token', Request::METHOD_OPTIONS, null, [
            'Access-Control-Request-Headers' => 'access_control_allow_headers',
        ]);

        self::assertEquals(Response::HTTP_OK, $response->getStatusCode());
        self::assertEquals('access_control_allow_headers', $response->headers->get('Access-Control-Allow-Headers'));
    }

    public function testAuthorizeShouldReturn400OnInvalidRequests(): void
    {
        $response = $this->request('/token', Request::METHOD_POST);
        self::assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());

        $response = $this->request('/token', Request::METHOD_GET);
        self::assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());

        $response = $this->request('/token', Request::METHOD_POST, ['grant_type' => 'unknown']);
        self::assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());

        $response = $this->request('/token', Request::METHOD_GET, ['grant_type' => 'unknown']);
        self::assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testAuthorizeShouldReturn200OnValidRequests(): void
    {
        foreach ([Request::METHOD_GET, Request::METHOD_POST] as $method) {
            $response = $this->request('/token', $method, [
                'client_id' => OAuthClient::FIXTURE_ID,
                'client_secret' => OAuthClient::FIXTURE_SECRET,
                'grant_type' => 'client_credentials',
            ]);

            self::assertEquals(Response::HTTP_OK, $response->getStatusCode());

            $responseBody = \json_decode($response->getContent(), true);
            self::assertArrayHasKey('access_token', $responseBody);
            self::assertArrayHasKey('expires_in', $responseBody);
            self::assertArrayHasKey('token_type', $responseBody);
            self::assertArrayHasKey('scope', $responseBody);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new AppKernel('test', true);
    }

    private function request(string $url, string $method, ?array $requestData = null, array $additionalHeaders = []): Response
    {
        $contentHeaders = ['content-length' => 'CONTENT_LENGTH', 'content-md5' => 'CONTENT_MD5', 'content-type' => 'CONTENT_TYPE'];
        $headers = [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ];

        foreach ($additionalHeaders as $header => $value) {
            $header = \strtolower($header);
            if (isset($contentHeaders[$header])) {
                $headers[$contentHeaders[$header]] = $value;
            } elseif ('PHP_AUTH_USER' === $header || 'PHP_AUTH_PW' === $header) {
                $headers[$header] = $value;
            } else {
                $headers['HTTP_'.\str_replace('-', '_', \strtoupper($header))] = $value;
            }
        }

        if (Request::METHOD_GET === $method && ! empty($requestData)) {
            $url .= '?'.\http_build_query($requestData);

            $requestData = null;
        }

        $client = static::createClient();
        $client->request($method, $url, [], [], $headers, null !== $requestData ? \json_encode($requestData) : null);

        return $client->getResponse();
    }
}
