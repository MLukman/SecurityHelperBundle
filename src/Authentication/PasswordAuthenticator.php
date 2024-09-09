<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Doctrine\ORM\EntityManagerInterface;
use Exception;
use MLukman\DoctrineHelperBundle\Service\ObjectValidator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Description of PasswordAuthenticator
 *
 * @author Lukman
 */
class PasswordAuthenticator extends AbstractAuthenticator
{

    const DEFAULT_REDIRECT_ROUTE = 'app_home';
    const LOGIN_ROUTE = 'security_login';

    use TargetPathTrait;

    public function __construct(protected AuthenticationListener $authListener,
            protected EntityManagerInterface $entityManager,
            protected ObjectValidator $validator,
            protected RouterInterface $router,
            protected UserPasswordHasherInterface $passwordEncoder,
            protected MailerInterface $mailer
    )
    {
        
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === self::LOGIN_ROUTE && $request->getMethod() == 'POST';
    }

    public function authenticate(Request $request): Passport
    {
        $this->authListener->loginFormPreAuthenticationChecks($request);

        $username = $request->request->get('username');
        $password = $request->request->get('password');

        if (empty($username) || empty($password)) { // empty input
            throw new CustomUserMessageAuthenticationException('Both username and password are required.');
        }

        // fetch user authentication entity
        try {
            $user_auth = $this->authListener->queryUserEntity('password', 'username', $username);
        } catch (Exception $ex) {
            throw new CustomUserMessageAuthenticationException($ex->getMessage());
        }

        if (!$user_auth) { // User not found
            throw new CustomUserMessageAuthenticationException('Invalid credentials');
        }

        if (($reset_code = $request->query->get('reset_code'))) {
            if ($reset_code != $user_auth->getResetCode()) {
                $this->authListener->log($user_auth, 'RESET_PASSWORD_FAILURE');
                throw new CustomUserMessageAuthenticationException('Invalid reset code.');
            }
            // reset password
            $user_auth->setPassword($this->passwordEncoder->hashPassword($user_auth, $password));
            $user_auth->setResetCode(null);
            $this->entityManager->flush();
            $this->entityManager->refresh($user_auth);
            $this->authListener->log($user_auth, 'RESET_PASSWORD_SUCCESS');
        } elseif (!$this->passwordEncoder->isPasswordValid($user_auth, $password)) {
            $this->authListener->log($user_auth, 'LOGIN_FAILURE');
            throw new CustomUserMessageAuthenticationException('Invalid credentials');
        }

        $user_auth->setAuthSession(bin2hex(random_bytes(16)));
        $this->entityManager->flush();

        return new SelfValidatingPassport(
                new UserBadge($user_auth->getUserIdentifier(), fn() => $user_auth),
                [new RememberMeBadge()]
        );
    }

    public function queryUserByUsername(string $username): ?UserEntity
    {
        return $this->authListener->queryUserEntity('password', 'username', $username);
    }

    public function registerNewUser(string $username, string $email): UserEntity|array
    {
        $user = $this->authListener->newUserEntity('password', $username, $username);
        $user->setEmail($email);
        if (($errors = $this->validator->validate($user))) {
            return $errors;
        }
        $this->entityManager->persist($user);
        $this->sendResetPasswordEmail($user);
        return $user;
    }

    public function sendResetPasswordEmail(UserEntity $user)
    {
        $user->setResetCode(md5($user->getEmail() . ':' . time()));
        $this->authListener->repo()->sendResetPasswordEmail($user);
        $this->entityManager->flush();
        $this->authListener->log($user, 'RESET_PASSWORD_EMAIL');
    }

    public function onAuthenticationFailure(Request $request,
            AuthenticationException $exception): ?Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);
        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $request->get('username'));
        return $this->authListener->handleAuthenticationFailure($request, $this, $exception);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse(
                $this->getTargetPath($request->getSession(), $firewallName) ?:
                $this->router->generate($this->authListener->getDefaultRedirectRoute()));
    }
}
