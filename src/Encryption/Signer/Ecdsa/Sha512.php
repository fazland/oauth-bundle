<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption\Signer\Ecdsa;

use Fazland\OAuthBundle\Encryption\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-512.
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 2.1.0
 */
final class Sha512 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): int
    {
        return \OPENSSL_ALGO_SHA512;
    }
}
