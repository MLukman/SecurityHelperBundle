<?php

namespace MLukman\SecurityHelperBundle\Util;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use function str_starts_with;

class Redirector
{
    public const COOKIEKEY = 'sf_security_redirect_after_login';

    private ?string $redirectUrl = null;

    public function __construct(private RequestStack $requestStack, private UrlGeneratorInterface $urlGenerator, private CookieInjector $cookieInjector) {}

    protected function storeRedirectUrl(?string $url, bool $overwrite)
    {
        if (!$overwrite && !empty($this->fetchRedirectUrl(false))) {
            return;
        }
        if ($url == $this->loginFullUrl()) {
            return;
        }
        if ($url) {
            $this->redirectUrl = $url;
            $this->cookieInjector->setCookie(self::COOKIEKEY, $this->redirectUrl);
        } else {
            $this->redirectUrl = null;
            $this->cookieInjector->removeCookie(self::COOKIEKEY);
        }
    }

    public function fetchRedirectUrl(bool $clear = true): ?string
    {
        $url = $this->redirectUrl;
        if ($this->cookieInjector->hasCookie(self::COOKIEKEY)) {
            $url = $this->cookieInjector->getCookie(self::COOKIEKEY);
        }
        if ($clear) {
            $this->clearRedirectUrl();
        }
        return $url;
    }

    public function clearRedirectUrl()
    {
        $this->redirectUrl = null;
        $this->cookieInjector->removeCookie(self::COOKIEKEY);
    }

    public function saveCurrentRequestUrl(bool $overwrite = false)
    {
        $this->storeRedirectUrl($this->request()->getSchemeAndHttpHost() . $this->request()->getRequestUri(), $overwrite);
    }

    public function saveRefererUrl(bool $overwrite = false)
    {
        $this->storeRedirectUrl($this->request()->headers->get('referer'), $overwrite);
    }

    public function generateRedirectResponse(): ?RedirectResponse
    {
        return ($url = $this->fetchRedirectUrl()) ?
            new RedirectResponse($url, RedirectResponse::HTTP_SEE_OTHER) : null;
    }

    private function loginFullUrl(): string
    {
        return $this->urlGenerator->generate('security_login', referenceType: UrlGeneratorInterface::ABSOLUTE_URL);
    }

    private function request(): Request
    {
        return $this->requestStack->getCurrentRequest();
    }
}
