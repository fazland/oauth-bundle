<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption\Signer;

use Lcobucci\JWT\Signer;

/**
 * Base class for ECDSA signers.
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 2.1.0
 */
abstract class Ecdsa implements Signer
{
    public static function create(): self
    {
        return new static();
    }

    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Signer\Key $key): string
    {
        $key = \openssl_get_privatekey($key->getContent(), $key->getPassphrase());
        $this->validateKey($key);

        $signature = '';

        if (! \openssl_sign($payload, $signature, $key, $this->getAlgorithm())) {
            throw new \InvalidArgumentException(
                'There was an error while creating the signature: '.\openssl_error_string()
            );
        }

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    final public function verify(string $expected, string $payload, Signer\Key $key): bool
    {
        $key = \openssl_get_publickey($key->getContent());
        $this->validateKey($key);

        return 1 === \openssl_verify($payload, $expected, $key, $this->getAlgorithm());
    }

    /**
     * Returns the name of algorithm to be used to create the signing hash.
     *
     * @return int
     */
    abstract public function getAlgorithm(): int;

    /**
     * Raise an exception when the key type is not the expected type.
     *
     * @param resource|bool $key
     *
     * @throws \InvalidArgumentException
     */
    private function validateKey($key): void
    {
        if (false === $key) {
            throw new \InvalidArgumentException(
                'It was not possible to parse your key, reason: '.\openssl_error_string()
            );
        }

        $details = \openssl_pkey_get_details($key);

        if (! isset($details['key']) || \OPENSSL_KEYTYPE_EC !== $details['type']) {
            throw new \InvalidArgumentException('This key is not compatible with RSA signatures');
        }
    }
}
