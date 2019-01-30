<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Enum;

use MyCLabs\Enum\Enum;

final class SignatureAlgorithm extends Enum
{
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';

    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';

    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
}
