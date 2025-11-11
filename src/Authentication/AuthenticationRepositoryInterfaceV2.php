<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

interface AuthenticationRepositoryInterfaceV2 extends AuthenticationRepositoryInterface
{

    public function beforeRedirectToLogin(Request $request, RedirectResponse $redirect): void;
}
