<?php

namespace MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use Stevenmaguire\OAuth2\Client\Provider\KeycloakResourceOwner;

/**
 * Description of KeycloakVisitor
 *
 * @author Lukman
 */
class KeycloakVisitor implements VisitorInterface
{

    public function prepareNewUserFromResourceOwner(UserEntity $user,
            ResourceOwnerInterface $resourceOwner)
    {
        if ($resourceOwner instanceof KeycloakResourceOwner) {
            $user->setFullname($resourceOwner->getName());
            $user->setEmail($resourceOwner->getEmail());
        }
    }

    public function prepareRedirectOptions(array &$options,
            OAuth2ClientInterface $client)
    {
        
    }
}
