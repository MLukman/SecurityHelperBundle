<?php

namespace MLukman\SecurityHelperBundle\Authorization;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * SecuredAccessVoter is Symfony Voter subclass which votes on objects which
 * implement SecuredAccessInterface.
 */
class SecuredAccessVoter extends Voter
{
    public function __construct(private Security $security)
    {
        
    }

    /**
     * Determines if the attribute and subject are supported by this voter.
     *
     * @param string $attribute An attribute
     * @param mixed  $subject   The subject to secure, e.g. an object the user wants to access or any other PHP type
     *
     * @return bool True if the attribute and subject are supported, false otherwise
     */
    protected function supports(string|array $attribute, mixed $subject): bool
    {
        return ($subject instanceof SecuredAccessInterface);
    }

    /**
     * Perform a single access check operation on a given attribute, subject and token.
     *
     * @param string         $attribute
     * @param mixed          $subject
     * @param TokenInterface $token
     *
     * @return bool
     */
    protected function voteOnAttribute(string|array $attribute, mixed $subject, TokenInterface $token): bool
    {
        if (is_array($attribute)) {
            foreach ($attribute as $attr) {
                if ($this->voteOnAttribute($attr, $subject, $token)) {
                    return true;
                }
            }
            return false;
        }

        /* @var $subject SecuredAccessInterface */
        return $subject->isAccessAllowed($token->getUserIdentifier(), $token->getRoleNames(), $attribute);
    }
}
