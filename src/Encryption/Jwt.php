<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption;

use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use Fazland\OAuthBundle\Storage\Jwt as StorageJwt;
use Lcobucci\Jose\Parsing\Parser as Decoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use OAuth2\Encryption\Jwt as BaseJwt;

class Jwt extends BaseJwt
{
    /**
     * @var ParserInterface
     */
    private $parser;

    public function __construct()
    {
        $this->parser = new Token\Parser(new Decoder());
    }

    public function encode($payload, $key, $algorithm = SignatureAlgorithm::HS256): string
    {
        $header = $this->generateJwtHeader($payload, $algorithm);

        $segments = [
            $this->urlSafeB64Encode(\json_encode($header)),
            $this->urlSafeB64Encode(\json_encode($payload)),
        ];

        $signingInput = \implode('.', $segments);

        $signer = SignerFactory::factory(new SignatureAlgorithm($algorithm));
        $signature = $signer->sign($signingInput, new Key($key));

        return \implode('.', [$signingInput, $this->urlSafeB64Encode($signature)]);
    }

    public function decode($jwt, $key = null, $allowedAlgorithms = true)
    {
        try {
            $token = $this->parser->parse($jwt);
        } catch (\InvalidArgumentException $ex) {
            return false;
        }

        $alg = $token->headers()->get('alg');
        if ((bool) $allowedAlgorithms) {
            if (empty($alg)) {
                return false;
            }

            // check if bool arg supplied here to maintain BC
            if (\is_array($allowedAlgorithms) && ! \in_array($alg, $allowedAlgorithms, true)) {
                return false;
            }

            if (null === $key) {
                return false;
            }

            if (! StorageJwt::verify($token, $key)) {
                return false;
            }
        }

        return \json_decode($this->urlSafeB64Decode(\explode('.', $token->payload())[1]), true);
    }
}
