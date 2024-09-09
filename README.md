# Security Helper Bundle

## About

Security Helper Bundle is a Symfony 7.x bundle that simplifies the implementation of AAA (authentication, authorization and audit) of a web application. It is a layer on top of the core Symfony Security Bundle.

## Installation

Make sure Composer is installed globally, as explained in the [installation chapter](https://getcomposer.org/doc/00-intro.md) of the Composer documentation.

### Applications that use Symfony Flex

Open a command console, enter your project directory and execute:

```shell
composer require mlukman/security-helper-bundle
```

### Applications that don't use Symfony Flex

#### Step 1: Download the Bundle

Open a command console, enter your project directory and execute the
following command to download the latest stable version of this bundle:

```shell
composer require mlukman/security-helper-bundle:1.*
```

#### Step 2: Enable the Bundle

Then, enable the bundle by adding it to the list of registered bundles
in the `config/bundles.php` file of your project:

```php
// config/bundles.php

return [
    // ...
    MLukman\SecurityHelperBundle\SecurityHelperBundle::class => ['all' => true],
];
```

## Activation

While Composer helps a lot in installing this bundle, there are some further steps that are required to activate this bundle in your web application.

### Create Doctrine entity that subclasses of UserEntity

Most of the columns configuration for authentication purposes are already implemented by the `UserEntity` class except the `#[ORM\Id]` field, which is intentionally left for the subclass to implement. Feel free to add relations as needed by your database design.

Example:

```php 
#[ORM\Entity]
#[ORM\Table]
class User extends UserEntity {
    
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    protected ?int $id = null;

    /**
     * You might want to override this method to handle the scenario where a user is already logged in
     * proceeds to login with a different method and/or credentials. Applicable forlogin using OAuth only.
     * Example: make both user entities share the same profile or account
     */
    public function merge(UserEntity $tobemerged)
    {
        
    }    
}
```

### Implement AuthenticationRepositoryInterface

The implementation class needs to implement the following methods:

#### getDefaultRedirectRoute() : string

This method should return the route to redirect to if the information about the previous route is not available. The returned route will also be used to redirect user after logout.

#### newUserEntity(string $method, string $credential, string $username = null): UserEntity

Create new User entity object. This method should not save the object to database yet.

#### queryUserEntity(string $method, string $criteriaField, string $criteriaValue): ?UserEntity

Query a User entity based on method, criteriaField and criteriaValue. This method may return null in no such entity can be found.

#### queryUserEntityFromSecurityUser(UserInterface $securityUser): ?UserEntity

Query a User entity based on the pass UserInterface object. This method may return null in no such entity can be found.

#### saveUserEntity(UserEntity $user): void

Save the passed new/modified User entity object.

#### sendResetPasswordEmail(UserEntity $user): void

Send a reset password email to the user.

### Implement LoginControllerInterface

The implementation class needs to implement the following method:

#### login(Request $request, ClientRegistry $clientRegistry): Response

Show login page that should contain one or more of the followings, depending on the authentication methods that you want to implement:

- Username & password input fields
- The buttons to login using OAuth2 providers

### Register both implementations of AuthenticationRepositoryInterface and  LoginControllerInterface

Add the following to your `services.yaml`:

```yaml
services:
    # existing settings here
   
   
    MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface:
        class: 'App\Service\AuthenticationRepository'
    
    MLukman\SecurityHelperBundle\Controller\LoginControllerInterface:
        class: 'App\Controller\AuthController'
   
```

### Register the bundle routing

Add a YAML file named `security_helper.yaml` with the following content into your `config/routes` folder (modify the `prefix` parameter to your preference):

```yaml
security_helper:
    resource: '@SecurityHelperBundle/src/Resources/config/routes.xml'
    prefix: /@auth
```

### Register with the main Symfony Security Bundle

Merge the following settings into your `config/packages/security.yaml`:

```yaml
security:
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User # follow your UserEntity subclass name
                property: username
    firewalls:
        main:
            provider: app_user_provider
            custom_authenticators: # remove authenticators you don't need
                - MLukman\SecurityHelperBundle\Authentication\PasswordAuthenticator
                - MLukman\SecurityHelperBundle\Authentication\LDAPAuthenticator
                - MLukman\SecurityHelperBundle\Authentication\OAuth2Authenticator
            entry_point: MLukman\SecurityHelperBundle\Authentication\AuthenticationListener
            logout:
                path: security_logout
    access_control:
        # ensure the routing prefix you defined in security_helper.yaml has PUBLIC_ACCESS access control
        - { path: ^/@auth/, roles: PUBLIC_ACCESS }
        # adjust based on your sitemap
        - { path: ^/admin/, roles: ROLE_ADMIN }
        - { path: ^/, roles: PUBLIC_ASSESS }

```

