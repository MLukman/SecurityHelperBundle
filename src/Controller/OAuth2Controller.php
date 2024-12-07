<?php

namespace MLukman\SecurityHelperBundle\Controller;

use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use MLukman\SecurityHelperBundle\Authentication\AuthenticationListener;
use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use MLukman\SecurityHelperBundle\Util\CookieInjector;
use MLukman\SecurityHelperBundle\Util\Redirector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Router;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Contracts\Service\Attribute\Required;

class OAuth2Controller extends AbstractController
{
    protected bool $useHtmlRedirect = false;
    protected RouterInterface $router;
    protected Redirector $redirector;
    protected CookieInjector $cookies;
    protected ClientRegistry $clientRegistry;
    protected AuthenticationListener $authListener;
    protected iterable $visitors;

    #[Required]
    public function setDependencies(
        RouterInterface $router,
        Redirector $redirector,
        CookieInjector $cookies,
        ClientRegistry $clientRegistry,
        AuthenticationListener $authListener,
        #[AutowireIterator('oauth2.authenticator.visitor')] iterable $visitors
    ) {
        $this->router = $router;
        $this->redirector = $redirector;
        $this->cookies = $cookies;
        $this->clientRegistry = $clientRegistry;
        $this->authListener = $authListener;
        $this->visitors = $visitors;
    }

    /**
     * Set to true to use HTML redirect (using <meta http-equiv="refresh" /> tag) instead of HTTP redirect
     * @param bool $useHtmlRedirect
     * @return void
     */
    public function setUseHtmlRedirect(bool $useHtmlRedirect): void
    {
        $this->useHtmlRedirect = $useHtmlRedirect;
    }

    public function connect(Request $request, $client): Response
    {
        // store remember me flag if any
        if ($request->query->get('remember')) {
            $this->cookies->setCookie('sf_security_remember', 1);
        } else {
            $this->cookies->removeCookie('sf_security_remember');
        }

        // store redirect after login into state
        $redirectAfterLogin = $this->redirector->fetchRedirectUrl(false) ?:
            $this->router->generate($this->authListener->getDefaultRedirectRoute(), referenceType: Router::ABSOLUTE_URL);
        $options = ['state' => rtrim(strtr(base64_encode($redirectAfterLogin), '+/', '-_'), '=')];

        // prepare redirect to provider
        $clientObj = $this->clientRegistry->getClient($client);
        foreach ($this->visitors as $visitor) {
            $visitor->prepareRedirectOptions($options, $clientObj);
        }
        $redirectResponse = $clientObj->redirect([], $options);
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

    public function check(): Response
    {
        throw new Exception('Implementation Error: application is required to implement and alias the interface ' . AuthenticationRepositoryInterface::class);
    }
}
