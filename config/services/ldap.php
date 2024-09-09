<?php

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Ldap\Adapter\ExtLdap\Adapter;
use Symfony\Component\Ldap\Ldap;

return static function (ContainerConfigurator $container): void {
    if (($host = $_ENV['LDAP_HOST'] ?? null) &&
        ($port = $_ENV['LDAP_PORT'] ?? null)) {
        $ldap_conn = [
            'host' => $host,
            'port' => $port,
            'encryption' => $_ENV['LDAP_ENCRYPTION'] ?: 'none',
            'options' => [
                'protocol_version' => 3,
                'referrals' => false
            ]
        ];
        $container->services()
            ->set(Ldap::class)
            ->args([new Reference(Adapter::class)])
            ->tag('ldap');
        $container->services()
            ->set(Adapter::class)
            ->arg(0, $ldap_conn);
    }
};
