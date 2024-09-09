<?php

namespace MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('oauth2.authenticator.visitor')]
interface VisitorInterface
{

    public function prepareRedirectOptions(array &$options, OAuth2ClientInterface $client);

    public function prepareNewUserFromResourceOwner(UserEntity $user, ResourceOwnerInterface $resourceOwner);
}
