<?php

namespace MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;

/**
 * Description of GoogleVisitor
 *
 * @author Lukman
 */
class GoogleVisitor implements VisitorInterface
{

    public function prepareNewUserFromResourceOwner(UserEntity $user, ResourceOwnerInterface $resourceOwner)
    {
        if ($resourceOwner instanceof GoogleUser) {
            $user->setEmail($resourceOwner->getEmail());
        }
    }

    public function prepareRedirectOptions(array &$options, OAuth2ClientInterface $client)
    {
        if ($client instanceof Google) {
            $options += ['prompt' => 'select_account'];
        }
    }
}
