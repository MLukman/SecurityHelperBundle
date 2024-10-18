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
    protected bool $useHtmlRedirect = false;

    /**
     * Set to true to use HTML redirect (using <meta http-equiv="refresh" /> tag) instead of HTTP redirect
     * @param bool $useHtmlRedirect
     * @return void
     */
    public function setUseHtmlRedirect(bool $useHtmlRedirect): void
    {
        $this->useHtmlRedirect = $useHtmlRedirect;
    }

    public function connect(OAuth2Authenticator $oauth2, Redirector $redirector, $client): Response
    {
        $redirector->saveRefererUrl(false);
        $redirectResponse = $oauth2->getRedirectionToProvider($client);
        if ($this->useHtmlRedirect) {
            $html = sprintf(
                '<!DOCTYPE html><html lang="en"><head><meta http-equiv="refresh" content="0; URL=%s" /></head><body><em>Redirecting to %s ...</em></body></html>',
                htmlentities($redirectResponse->getTargetUrl()),
                $client
            );
            return new Response($html, 200, ['Content-Type' => 'text/html']);
        } else {
            return $redirectResponse;
        }
    }

    public function check(OAuth2Authenticator $oauth2, Request $request): Response
    {
        throw new Exception('Implementation Error: application is required to implement and alias the interface ' . AuthenticationRepositoryInterface::class);
    }
}
