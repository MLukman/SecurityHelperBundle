<?php

namespace MLukman\SecurityHelperBundle\Util;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class Redirector
{
    public function __construct(private RequestStack $requestStack, private UrlGeneratorInterface $urlGenerator)
    {

    }

    protected function storeRedirectUrl(?string $url, bool $overwrite)
    {
        if (!$overwrite && !empty($this->fetchRedirectUrl(false))) {
            return;
        }
        if ($url == $this->loginFullUrl()) {
            return;
        }
        if ($url) {
            $this->requestStack->getSession()->set('_redirector_stored_url', $url);
        } else {
            $this->requestStack->getSession()->remove('_redirector_stored_url');
        }
    }

    public function fetchRedirectUrl(bool $clear = true): ?string
    {
        $url = $this->requestStack->getSession()->get('_redirector_stored_url');
        if ($clear) {
            $this->requestStack->getSession()->remove('_redirector_stored_url');
        }
        if (!$url && ($referer = $this->requestStack->getCurrentRequest()->headers->get('referer')) && $referer != $this->loginFullUrl()) {
            return $referer;
        }
        return $url;
    }

    public function saveCurrentRequestUrl(bool $overwrite = true)
    {
        $this->storeRedirectUrl($this->requestStack->getCurrentRequest()->getSchemeAndHttpHost() . $this->requestStack->getCurrentRequest()->getRequestUri(), $overwrite);
    }

    public function saveRefererUrl(bool $overwrite = true)
    {
        $this->storeRedirectUrl($this->requestStack->getCurrentRequest()->headers->get('referer'), $overwrite);
    }

    public function generateRedirectResponse(): ?RedirectResponse
    {
        return ($url = $this->fetchRedirectUrl()) ?
            new RedirectResponse($url) : null;
    }

    private function loginFullUrl(): string
    {
        return $this->urlGenerator->generate('security_login', referenceType: UrlGeneratorInterface::ABSOLUTE_URL);
    }
}
