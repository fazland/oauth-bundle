<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Firewall;

use Fazland\OAuthBundle\Security\Firewall\OAuthEntryPoint;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuthEntryPointTest extends TestCase
{
    /**
     * @var OAuthEntryPoint|ObjectProphecy
     */
    private $entryPoint;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        $this->entryPoint = new OAuthEntryPoint();
    }

    public function testStartShouldReturnUnauthorizedJsonResponse(): void
    {
        $data = [
            'error' => 'access_denied',
            'error_description' => 'OAuth authentication required',
        ];

        $headers = ['Cache-Control' => 'no-store'];

        $response = JsonResponse::create($data, Response::HTTP_UNAUTHORIZED, $headers);
        $request = $this->prophesize(Request::class);

        self::assertEquals($response, $this->entryPoint->start($request->reveal()));
    }
}
