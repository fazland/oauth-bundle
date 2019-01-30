<?php declare(strict_types=1);

namespace App\Tests\Encryption;

use Fazland\OAuthBundle\Encryption\SignerFactory;
use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use PHPUnit\Framework\TestCase;

class SignerFactoryTest extends TestCase
{
    public function dataProviderForFactoryAlgorithms(): iterable
    {
        foreach (SignatureAlgorithm::values() as $algorithm) {
            yield [$algorithm];
        }
    }

    /**
     * @dataProvider dataProviderForFactoryAlgorithms
     */
    public function testFactoryWorksForAlgorithms(SignatureAlgorithm $algorithm): void
    {
        self::assertNotNull(SignerFactory::factory($algorithm));
    }
}
