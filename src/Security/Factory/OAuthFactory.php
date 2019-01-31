<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Factory;

use Fazland\OAuthBundle\DependencyInjection\Reference as OAuthReference;
use Fazland\OAuthBundle\GrantType;
use Fazland\OAuthBundle\Security\Firewall\OAuthEntryPoint;
use Fazland\OAuthBundle\Security\Firewall\OAuthFirewall;
use Fazland\OAuthBundle\Security\Provider\OAuthProvider;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class OAuthFactory implements SecurityFactoryInterface
{
    public const USER_PROVIDERS_PARAMETER_NAME = 'fazland_oauth.user_providers';

    /**
     * {@inheritdoc}
     */
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint): array
    {
        $providerId = $this->createAuthenticationProvider($container, $id, $config);
        $clientCredentialsStorageId = $this->createClientCredentialsStorage($container, $id, $config);
        $jwtStorageId = $this->createJwtStorage($container, $id, $config);
        $jwtResponseTypeId = $this->createJwtResponseType($container, $id, $config);

        $serverId = $this->createServer($container, $id, $config, $clientCredentialsStorageId, $jwtStorageId, $jwtResponseTypeId);

        $listenerId = 'security.authentication.listener.oauth.'.$id;
        $container->setDefinition($listenerId, new Definition(OAuthFirewall::class))
            ->addArgument(new Reference($serverId))
            ->addArgument(new Reference('security.token_storage'))
            ->addArgument(new Reference('security.authentication.manager'))
        ;

        $userProvidersId = self::USER_PROVIDERS_PARAMETER_NAME;

        $userProviders = $container->hasParameter($userProvidersId) ? $container->getParameter($userProvidersId) : [];
        $userProviders[$id] = $config['oauth_user_provider'];
        $container->setParameter($userProvidersId, $userProviders);

        return [$providerId, $listenerId, OAuthEntryPoint::class];
    }

    /**
     * {@inheritdoc}
     */
    public function getPosition(): string
    {
        return 'pre_auth';
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'oauth';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
            ->scalarNode('oauth_user_provider')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('access_token_storage')->end()
            ->scalarNode('refresh_token_storage')->end()
            ->scalarNode('client_credentials_storage')
            ->defaultValue('fazland_oauth.storage.client_credentials.abstract')
            ->end()
            ->scalarNode('jwt_storage')
            ->defaultValue('fazland_oauth.storage.jwt.abstract')
            ->end()
            ->scalarNode('jwt_issuer')
            ->defaultValue('app')
            ->end()
            ->arrayNode('server')
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('grant_types')
            ->prototype('scalar')->end()
            ->end()
            ->arrayNode('storage')
            ->prototype('scalar')->end()
            ->end()
            ->arrayNode('response_types')
            ->prototype('scalar')->end()
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    private function createAuthenticationProvider(ContainerBuilder $container, string $id, array $config): string
    {
        $oauthProvider = $config['oauth_user_provider'];

        $providerId = 'security.authentication.provider.oauth.'.$id;
        $container
            ->register($providerId, OAuthProvider::class)
            ->setArgument(0, new OAuthReference($oauthProvider))
        ;

        return $providerId;
    }

    private function createClientCredentialsStorage(ContainerBuilder $container, string $id, array $config): ?string
    {
        $clientCredentialsStorageId = $config['client_credentials_storage'] ?: null;
        if (null === $clientCredentialsStorageId) {
            return null;
        }

        $storageId = $clientCredentialsStorageId;
        if ('fazland_oauth.storage.client_credentials.abstract' === $clientCredentialsStorageId) {
            $definition = new ChildDefinition($clientCredentialsStorageId);
            $definition->replaceArgument(0, new OAuthReference($config['oauth_user_provider']));

            $storageId = 'fazland_oauth.storage.client_credentials.'.$id;
            $container->setDefinition($storageId, $definition);
        }

        return $storageId;
    }

    private function createJwtStorage(ContainerBuilder $container, string $id, array $config): ?string
    {
        $jwtStorageId = $config['jwt_storage'] ?: null;
        if (null === $jwtStorageId) {
            return null;
        }

        $storageId = $jwtStorageId;
        if ('fazland_oauth.storage.jwt.abstract' === $jwtStorageId) {
            $definition = new ChildDefinition($jwtStorageId);
            $definition
                ->replaceArgument(0, new OAuthReference($config['oauth_user_provider']))
                ->replaceArgument(1, ['iss' => $config['jwt_issuer']])
            ;

            $storageId = 'fazland_oauth.storage.jwt.'.$id;
            $container->setDefinition($storageId, $definition);
        }

        return $storageId;
    }

    private function createJwtResponseType(ContainerBuilder $container, string $id, array $config): ?string
    {
        $jwtResponseTypeId = 'fazland_oauth.response_type.jwt_access_token.'.$id;
        $container->setDefinition($jwtResponseTypeId, new ChildDefinition('fazland_oauth.response_type.jwt_access_token.abstract'))
            ->setArgument(0, new OAuthReference($config['oauth_user_provider']))
            ->setArgument(1, isset($config['access_token_storage']) ? new OAuthReference($config['access_token_storage']) : null)
            ->setArgument(2, isset($config['refresh_token_storage']) ? new OAuthReference($config['refresh_token_storage']) : null)
            ->setArgument(3, ['iss' => $config['jwt_issuer']])
        ;

        return $jwtResponseTypeId;
    }

    private function createServer(
        ContainerBuilder $container,
        string $id,
        array $config,
        ?string $clientCredentialsStorageId,
        ?string $jwtStorageId,
        string $jwtResponseTypeId
    ): string {
        $serverId = 'fazland_oauth.server.'.$id;
        $serverDefinition = $container->setDefinition($serverId, new ChildDefinition('fazland_oauth.server.abstract'));
        $serverDefinition->addMethodCall('addResponseType', [new OAuthReference($jwtResponseTypeId)]);

        if (null !== $clientCredentialsStorageId) {
            $grantTypeDefinition = new Definition(GrantType\ClientCredentials::class, [new OAuthReference($clientCredentialsStorageId)]);
            $serverDefinition->addMethodCall('addGrantType', [$grantTypeDefinition]);
        }

        if (null !== $jwtStorageId) {
            $serverDefinition->addMethodCall('addStorage', [new OAuthReference($jwtStorageId)]);
        }

        foreach (['grant_types' => 'addGrantType', 'storage' => 'addStorage', 'response_types' => 'addResponseType'] as $key => $method) {
            foreach ($config['server'][$key] as $referenceId) {
                $serverDefinition->addMethodCall($method, [new OAuthReference($referenceId)]);
            }
        }

        return $serverId;
    }
}
