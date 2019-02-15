<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Clock;

use Cake\Chronos\Chronos;
use Lcobucci\Clock\Clock;

final class ChronosClock implements Clock
{
    /**
     * {@inheritdoc}
     */
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable(Chronos::now()->toAtomString());
    }
}
