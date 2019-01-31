<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Command;

use Fazland\OAuthBundle\Security\Provider\UserProviderInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class CreateClient extends Command
{
    /**
     * @var UserProviderInterface[]
     */
    private $userProviders;

    public function __construct()
    {
        parent::__construct('fazland:oauth:create-client');

        $this->userProviders = [];
    }

    public function addUserProvider(string $firewall, UserProviderInterface $userProvider): void
    {
        if (isset($this->userProviders[$firewall])) {
            throw new \RuntimeException(UserProviderInterface::class.' already set for firewall '.$firewall);
        }

        $this->userProviders[$firewall] = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->addArgument('name', InputArgument::REQUIRED)
            ->setDescription('Creates a new OAuthClient using the UserProvider obtained by the specified firewall')
            ->addOption('firewall', null, InputOption::VALUE_REQUIRED, 'Target firewall name')
            ->addOption('redirect-uri', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Specify client redirect uris')
            ->addOption('grant-type', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Specify client allowed grant types')
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): void
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Fazland - Create OAuth Client');

        $countUserProviders = \count($this->userProviders);
        if (0 === $countUserProviders) {
            throw new \RuntimeException('Cannot create an OAuth client without an implementation of '.UserProviderInterface::class);
        }

        /** @var UserProviderInterface|null $userProvider */
        $userProvider = null;

        $targetFirewallName = $input->getOption('firewall');
        if (null !== $targetFirewallName) {

            $filteredUserProviders = \array_filter($this->userProviders, function (string $firewallName) use ($targetFirewallName): bool {
                return $targetFirewallName === $firewallName;
            }, ARRAY_FILTER_USE_KEY);

            if (0 === \count($filteredUserProviders)) {
                throw new \RuntimeException(\sprintf(
                    'Could not find the desired %s implementation using %s as firewall name',
                    UserProviderInterface::class,
                    $targetFirewallName
                ));
            }

            $userProvider = \current($filteredUserProviders);
        } elseif (1 === $countUserProviders) {
            $userProvider = \current($this->userProviders);
        }

        if (null === $userProvider) {
            throw new \RuntimeException('Please, specify for which firewall I have to create the client.');
        }

        $clientName = $input->getArgument('name');

        $redirectUris = $input->getOption('redirect-uri');
        if (! \is_array($redirectUris)) {
            $redirectUris = [$redirectUris];
        }

        $grantTypes = $input->getOption('grant-type');
        if (! \is_array($grantTypes)) {
            $grantTypes = [$grantTypes];
        }

        $client = $userProvider->createClient($clientName, $redirectUris, $grantTypes);

        $io->table([], [
            ['Client ID', $client->getId()],
            ['Client Secret', $client->getSecret()],
        ]);

        $io->success('OAuthClient Successfully created!');
    }
}
