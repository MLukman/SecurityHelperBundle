<?php

namespace MLukman\SecurityHelperBundle;

use MLukman\SecurityHelperBundle\Audit\AuditLoggerInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class SecurityHelperBundle extends AbstractBundle
{
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.yaml');
        $builder->registerForAutoconfiguration(AuditLoggerInterface::class)
            ->addTag('security.audit.logger');
    }

    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $configs = $builder->getExtensionConfig('knpu_oauth2_client');
        foreach (array_reverse($configs) as &$config) {
            foreach ($config['clients'] ?? [] as $clientId => &$clientCfg) {
                if (!isset($clientCfg['redirect_route'])) {
                    $config['clients'][$clientId]['redirect_route'] = 'security_oauth2_connect_check';
                    $config['clients'][$clientId]['redirect_params'] = ['client' => $clientId];
                }
            }
            $builder->prependExtensionConfig('knpu_oauth2_client', [
                'clients' => $config['clients']
            ]);
        }
    }
}
