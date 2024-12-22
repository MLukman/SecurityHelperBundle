<?php

namespace MLukman\SecurityHelperBundle\Authorization;

/**
 * SecuredAccessInterface defines class signature for object that holds authorization
 * information such as which users and roles are allowed access to the object.
 */
interface SecuredAccessInterface
{
    /**
     * Check if a specific user role is allowed to access
     * @param string $role User role
     * @param string $attribute Attribute
     * @return bool
     */
    public function isAccessAllowed(string $userIdentifier, array $roles, string $attribute): bool;
}
