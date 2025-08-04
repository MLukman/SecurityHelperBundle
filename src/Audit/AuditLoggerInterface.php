<?php

namespace MLukman\SecurityHelperBundle\Audit;

use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use MLukman\SecurityHelperBundle\Util\SecurityEvent;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('security.audit.logger')]
interface AuditLoggerInterface
{

    public function logAuthentication(UserEntity $user, SecurityEvent $event, array $details = []): void;
}
