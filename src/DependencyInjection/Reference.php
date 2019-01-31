<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerInterface;

class Reference
{
    /**
     * @var string
     */
    private $id;

    /**
     * @var int
     */
    private $invalidBehavior;

    public function __construct(string $id, int $invalidBehavior = ContainerInterface::EXCEPTION_ON_INVALID_REFERENCE)
    {
        $this->id = $id;
        $this->invalidBehavior = $invalidBehavior;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->id;
    }

    /**
     * Returns the behavior to be used when the service does not exist.
     *
     * @return int
     */
    public function getInvalidBehavior(): int
    {
        return $this->invalidBehavior;
    }
}
