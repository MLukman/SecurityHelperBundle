<?php

namespace MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\FacebookUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;

/**
 * Description of FacebookVisitor
 *
 * @author Lukman
 */
class FacebookVisitor implements VisitorInterface
{
    public function prepareNewUserFromResourceOwner(UserEntity $user, ResourceOwnerInterface $resourceOwner)
    {
        if ($resourceOwner instanceof FacebookUser) {
            $user->setFullname($resourceOwner->getName());
            $user->setEmail($resourceOwner->getEmail());
        }
    }

    public function prepareRedirectOptions(array &$options, OAuth2ClientInterface $client)
    {

    }
}
