<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('contao_google_sso');

        $treeBuilder->getRootNode()
            ->children()
            ->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('client_secret')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('allowed_domains')
            ->info('Google Workspace domains (hd claim and email domain) that may log in.')
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->booleanNode('auto_create_users')
            ->info('Create a backend user on first SSO login if no user with that email exists.')
            ->defaultFalse()
            ->end()
            ->booleanNode('select_account')
            ->info('Always show Google\'s account chooser. If false, Google signs in without a click when the browser has only one matching account.')
            ->defaultTrue()
            ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
