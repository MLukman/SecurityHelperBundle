<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Exception;
use MLukman\SecurityHelperBundle\Util\SecurityEvent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Service\Attribute\Required;

class LDAPAuthenticator extends PasswordAuthenticator
{
    protected ?Ldap $ldap;

    #[Required]
    public function requiredByLdapAuth(?Ldap $ldap)
    {

        $this->ldap = $ldap;
    }

    public function supports(Request $request): ?bool
    {
        return parent::supports($request) && !empty($this->ldap);
    }

    public function authenticate(Request $request): Passport
    {
        $this->authListener->loginFormPreAuthenticationChecks($request);

        $username = $request->request->get('username');
        $password = $request->request->get('password');

        if (empty($username) || empty($password)) { // empty input
            throw new CustomUserMessageAuthenticationException('Both username and password are required.');
        }

        $baseDn = $_ENV['LDAP_BASE_DN'];
        $uidKey = $_ENV['LDAP_UID_KEY'];
        $uidFilter = sprintf("%s=%s", $uidKey, $username);
        $emailAttr = $_ENV['LDAP_EMAIL_ATTR'];

        $newUserEmail = null;
        try {
            if (
                ($searchDn = $_ENV['LDAP_SEARCH_DN']) &&
                // If search DN, password & filter are provided, use LDAP query to find the user DN
                ($searchPassword = $_ENV['LDAP_SEARCH_PASSWORD']) &&
                ($searchFilter = $_ENV['LDAP_SEARCH_FILTER'])
            ) {
                $this->ldap->bind($searchDn, $searchPassword);
                $filter = str_replace(
                    ['{uid_key}', '{username}'],
                    [$uidKey, $username],
                    $searchFilter
                );
                $entries = $this->ldap->query($baseDn, $filter)->execute();
                if ($entries->count() != 1) {
                    throw new CustomUserMessageAuthenticationException("LDAP account matching your username: " . $entries->count());
                }
                $userDn = $entries[0]->getDn();
                if (($emailAttribute = $entries[0]->getAttribute($emailAttr))) {
                    $newUserEmail = $emailAttribute[0];
                }
            } else {
                // Else simply construct the user DN using pattern: {uid_key}={username},{base_dn}
                $userDn = sprintf("%s,%s", $uidFilter, $baseDn);
            }
        } catch (InvalidCredentialsException $ex) {
            throw new CustomUserMessageAuthenticationException("LDAP failed to bind to the configured search account. Please contact admin.");
        } catch (ConnectionException $ex) {
            throw new CustomUserMessageAuthenticationException($ex->getMessage());
        }

        // fetch user authentication entity
        /** @var UserEntity $user_auth */
        try {
            $user_auth = $this->authListener->queryUserEntity('ldap', 'username', $userDn);
        } catch (Exception $ex) {
            throw new CustomUserMessageAuthenticationException($ex->getMessage());
        }

        try {
            // Bind using user DN & password
            $this->ldap->bind($userDn, $password);
        } catch (InvalidCredentialsException $ex) {
            if ($user_auth) {
                $this->authListener->log($user_auth, SecurityEvent::LOGIN_FAILURE);
            }
            throw new CustomUserMessageAuthenticationException($ex->getMessage());
        } catch (ConnectionException $ex) {
            throw new CustomUserMessageAuthenticationException($ex->getMessage());
        }

        if (!$user_auth) {
            $user_auth = $this->authListener->repo()->newUserEntity('ldap', $userDn, $userDn);
            // get & populate email
            if (empty($newUserEmail) &&
                ($entries = $this->ldap->query($baseDn, $uidFilter)->execute()) &&
                ($emailAttribute = $entries[0]->getAttribute($emailAttr))) {
                $newUserEmail = $emailAttribute[0];
            }
            $user_auth->setEmail($newUserEmail ?: $username . "@ldap");
            $this->auditLogger->log($user_auth, SecurityEvent::REGISTER);
        }

        $user_auth->setAuthSession(bin2hex(random_bytes(16)));
        $this->authListener->repo()->saveUserEntity($user_auth);

        return new SelfValidatingPassport(
            new UserBadge($user_auth->getUserIdentifier(), fn() => $user_auth),
            [new RememberMeBadge()]
        );
    }
}
