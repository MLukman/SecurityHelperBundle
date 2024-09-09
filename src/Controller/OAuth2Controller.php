<?php

namespace MLukman\SecurityHelperBundle\Controller;

use Exception;
use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator;
use MLukman\SecurityHelperBundle\Util\Redirector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuth2Controller extends AbstractController
{

    public function connect(OAuth2Authenticator $oauth2, Redirector $redirector, $client): Response
    {
        $redirector->saveRefererUrl(false);
        return $oauth2->getRedirectionToProvider($client);
    }

    public function check(OAuth2Authenticator $oauth2, Request $request): Response
    {
        throw new Exception('Implementation Error: application is required to implement and alias the interface ' . AuthenticationRepositoryInterface::class);
    }
}
