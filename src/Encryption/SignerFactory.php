<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption;

use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Rsa;

class SignerFactory
{
    /**
     * Gets a signer for the given algorithm.
     * $alg can be one of the following:
     *  - ES256, ES384, ES512 (for ECDSA)
     *  - HS256, HS384, HS512 (for HMAC Sha)
     *  - RS256, RS384, RS512 (for RSA Sha).
     *
     * @param SignatureAlgorithm $alg
     *
     * @return Signer
     */
    public static function factory(SignatureAlgorithm $alg): Signer
    {
        switch ($alg) {
            case SignatureAlgorithm::ES256():
                return Ecdsa\Sha256::create();
            case SignatureAlgorithm::ES384():
                return Ecdsa\Sha384::create();
            case SignatureAlgorithm::ES512():
                return Ecdsa\Sha512::create();
            case SignatureAlgorithm::HS256():
                return new Hmac\Sha256();
            case SignatureAlgorithm::HS384():
                return new Hmac\Sha384();
            case SignatureAlgorithm::HS512():
                return new Hmac\Sha512();
            case SignatureAlgorithm::RS256():
                return new Rsa\Sha256();
            case SignatureAlgorithm::RS384():
                return new Rsa\Sha384();
            case SignatureAlgorithm::RS512():
                return new Rsa\Sha512();
        }
    }
}
