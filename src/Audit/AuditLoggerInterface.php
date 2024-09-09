<?php

namespace MLukman\SecurityHelperBundle\Audit;

use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('security.audit.logger')]
interface AuditLoggerInterface
{

    public function logAuthentication(UserEntity $user, string $event, array $details = []): void;
}
