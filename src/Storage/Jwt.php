<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Storage;

use Cake\Chronos\Chronos;
use Fazland\OAuthBundle\Clock\ChronosClock;
use Fazland\OAuthBundle\Encryption\KeyPair\KeyPairInterface;
use Fazland\OAuthBundle\Encryption\SignerFactory;
use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Lcobucci\Jose\Parsing\Parser as Decoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Validation\Validator;
use OAuth2\Storage\JwtAccessTokenInterface;
use OAuth2\Storage\JwtBearerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;

class Jwt implements JwtAccessTokenInterface, JwtBearerInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var array
     */
    private $config;

    /**
     * @var Parser
     */
    private $parser;

    public function __construct(UserProviderInterface $userProvider, array $config)
    {
        if (! isset($config['iss']) || ! \is_string($config['iss'])) {
            throw new \InvalidArgumentException('Missing or invalid "iss" configuration key. It must be a string');
        }

        $this->userProvider = $userProvider;
        $this->config = $config;
        $this->parser = new Token\Parser(new Decoder());
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($oauthToken): ?array
    {
        try {
            $token = $this->parser->parse($oauthToken);
        } catch (\InvalidArgumentException | \RuntimeException | \TypeError $ex) {
            $this->logger->error('Exception while parsing token: '.$ex->getMessage(), [
                'exception' => $ex,
            ]);

            return null;
        }

        /** @var Token\DataSet $tokenClaims */
        $tokenClaims = $token->claims();

        $validator = new Validator();
        if (! $validator->validate(
            $token,
            new ValidAt(new ChronosClock()),
            new IssuedBy($this->config['iss'])
        )) {
            $this->logger->error('Token validation failed', [
                'token' => $oauthToken,
                'now' => Chronos::now()->getTimestamp(),
                'issued_at' => $tokenClaims->get(Token\RegisteredClaims::ISSUED_AT),
                'not_before' => $tokenClaims->get(Token\RegisteredClaims::NOT_BEFORE),
                'expiration' => $tokenClaims->get(Token\RegisteredClaims::EXPIRATION_TIME),
            ]);

            return null;
        }

        $clientId = $tokenClaims->get('aud')[0] ?? null;
        $subject = $tokenClaims->get('sub');

        $key = null !== $clientId ? $this->getKeyPair($tokenClaims) : null;
        if (null === $key) {
            $this->logger->error('No client key for: '.$clientId.' - '.$subject, [
                'token' => $oauthToken,
            ]);

            return null;
        }

        if (! self::verify($token, $key->getPublicKey())) {
            $this->logger->error('Failed to verify token. '.$clientId.' - '.$subject, [
                'token' => $oauthToken,
            ]);

            return null;
        }

        return $this->convertTokenToOAuth($token);
    }

    /**
     * {@inheritdoc}
     */
    public function setAccessToken($oauthToken, $clientId, $userId, $expires, $scope = null): void
    {
        // Do nothing.
    }

    /**
     * {@inheritdoc}
     */
    public function getClientKey($clientId, $subject)
    {
        return false;
    }

    /**
     * {@inheritdoc}
     *
     * @codeCoverageIgnore
     */
    public function getJti($clientId, $subject, $audience, $expiration, $jti): ?array
    {
        return null;
    }

    /**
     * {@inheritdoc}
     *
     * @codeCoverageIgnore
     */
    public function setJti($clientId, $subject, $audience, $expiration, $jti): void
    {
        // do nothing
    }

    public static function verify(Token $token, string $key): bool
    {
        $alg = $token->headers()->get('alg') ?? null;
        if (! SignatureAlgorithm::isValid($alg)) {
            return false;
        }

        $signer = SignerFactory::factory(new SignatureAlgorithm($alg));

        return $signer->verify($token->signature()->hash(), $token->payload(), new Key($key));
    }

    /**
     * Converts a Token object into an array understood by OAuth server library.
     *
     * @param Token $token
     *
     * @return array
     */
    private function convertTokenToOAuth(Token $token): array
    {
        return \iterator_to_array($this->traverseAndTranslatePayload($token));
    }

    private function traverseAndTranslatePayload(Token $token): \Generator
    {
        foreach ($token->claims()->all() as $name => $claim) {
            switch ($name) {
                case 'aud':
                    $name = 'client_id';

                    break;

                case 'exp':
                    $name = 'expires';
                    if ($claim instanceof \DateTimeInterface) {
                        $claim = $claim->getTimestamp();
                    }

                    break;

                case 'sub':
                    $name = 'user_id';

                    break;
            }

            yield $name => $claim;
        }
    }

    private function getKeyPair(Token\DataSet $tokenClaims): ?KeyPairInterface
    {
        $allClaims = $tokenClaims->all();

        $client = $this->userProvider->provideClient($allClaims);
        if (null === $client) {
            return null;
        }

        $subject = $tokenClaims->get('sub');
        if (null === $subject) {
            return $client;
        }

        $user = $this->userProvider->provideUser($allClaims);
        if (null === $user) {
            return null;
        }

        return $user instanceof KeyPairInterface ? $user : $client;
    }
}
