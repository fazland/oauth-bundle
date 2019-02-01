<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Fixtures\Token;

use Fazland\OAuthBundle\Encryption\KeyPair\KeyPairTrait;
use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use Fazland\OAuthBundle\GrantType\ClientCredentials;
use Fazland\OAuthBundle\Security\User\OAuthClientInterface;

class OAuthClient implements OAuthClientInterface
{
    public const FIXTURE_ID = '6154047f42b642baa142f83439a9c870';
    public const FIXTURE_SECRET = 'f902b74f31ea436ab614fcf717f3daf3c1477c9483474b55b613bc1985149c0f';

    use KeyPairTrait;

    public function __construct()
    {
        $this->privateKey = '-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANAG2ht/Htaj8Xo0
CLpUaxa7YaxdvrzGOH6ZLpyEB9VeHJq2yyvGNP7RW41dNJpwOh26SitGqplf81GA
aBFapxUvxlvEyZ+0R0JPnUbA96oGDhCLxOZ+cqZWaEflCXXaeNDc8Hft9JtU+uS+
FCX1qq81NERfnlfkCSwrcwzqzAEtAgMBAAECgYEAumNpSPm9R9PcqQG2UD0TNmru
OOJF5B42wDe/67zgx+xq9LSTlcUh9q7euOqqFzY23CvuCJhogsPV31CN7f6rdFDj
rv6h8vdFTA8m7bteFMz5wc8xD9tp1tmZdZIBHZCCBK9blhQWK3uZOcEhzuN8ucnb
zM8tQfIauxTZuqK4noECQQD9Ur/YksKfom3K62oL6UzeAb4B4+CWoKPdHovmh2lj
fBML2jYbiOXMMmlJ/FbpN0mr9GU6kLsRXN2lc2XoDN9zAkEA0jmS2DDJt+dclyqw
5CipJBQSC9HSF9bQGIlskDJSJIn45J355/3HCPjMiHsR2cIXhYczo8DyfA1ZDugB
/IY03wJAMEc2/MVrhhTkq8mV2lNKLP1UAvQ090ACOr/5laO0+BrLXnTl3vWGJhZt
boZC4guBZN4c9L5kiHiUXVXS1Biv9QJBALNogxORf3U9M92mh1QQB1lM76G6rSu/
HdTy4v2klEmungStdWsxPz0+537KWQ+X/u7r1Xw43DhWQ9zez2MtPc0CQF1nJKfU
33rZNmgzSpB0VUFhtApsfRPNp5k3jLZL8IV+UWULvmOOm6kVs+hQYPPSM5crlEOw
09NyArd5+kkcGiY=
-----END PRIVATE KEY-----
';
        $this->publicKey = '';
        $this->signatureAlgorithm = SignatureAlgorithm::RS256();
    }

    /**
     * {@inheritdoc}
     */
    public function getId(): string
    {
        return self::FIXTURE_ID;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecret(): ?string
    {
        return self::FIXTURE_SECRET;
    }

    /**
     * {@inheritdoc}
     */
    public function getScope(): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUris(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantTypes(): array
    {
        return [ClientCredentials::NAME];
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword(): ?string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt(): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername(): string
    {
        return 'user_'.\mt_rand();
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
    }
}
