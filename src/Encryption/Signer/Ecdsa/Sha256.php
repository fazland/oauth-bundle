<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption\Signer\Ecdsa;

use Fazland\OAuthBundle\Encryption\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-256.
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 2.1.0
 */
final class Sha256 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): int
    {
        return \OPENSSL_ALGO_SHA256;
    }
}
