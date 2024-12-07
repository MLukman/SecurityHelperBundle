<?php

namespace MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;

/**
 * Description of GithubVisitor
 *
 * @author Lukman
 */
class GithubVisitor implements VisitorInterface
{
    public function prepareNewUserFromResourceOwner(UserEntity $user, ResourceOwnerInterface $resourceOwner)
    {
        if ($resourceOwner instanceof GithubResourceOwner) {
            $user->setFullname($resourceOwner->getName());
            $user->setEmail($resourceOwner->getEmail());
        }
    }

    public function prepareRedirectOptions(array &$options, OAuth2ClientInterface $client)
    {
        if ($client instanceof GithubClient) {

        }
    }
}
