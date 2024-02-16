# Contao Google SSO Bundle

Adds a new login url (`/contao/login_sso`) to log into the Contao backend using existing users
inside a Google Workspace instance.

## Installation

Install the bundle via composer: `composer require boogiebaeren/contao-google-sso-bundle`
or install it via the Contao Manager.

## Configuration

You need to define two environment variables:

- GOOGLE_SSO_CLIENTID
- GOOGLE_SSO_CLIENTSECRET

You then need to add the following configuration to your `config/config.yaml` file:

```yaml
# config/config.yaml
contao_google_sso:
  client_id: '%env(GOOGLE_SSO_CLIENTID)%'
  client_secret: '%env(GOOGLE_SSO_CLIENTSECRET)%'
  hosted_domain: your-google-workspace-domain-name
```

You should also add the following to your `composer.json` file to remove all unused Google Services:

```json
{
  "extra": {
    "google/apiclient-services": [
      "Oauth2"
    ]
  },
  "scripts": {
    "pre-autoload-dump": "Google\\Task\\Composer::cleanup"
  }
}
```

You need to be an administrator of a Google Workspace instance to create a new OAuth client.
First create a new project inside the [Google Cloud Console](https://console.cloud.google.com/),
then create a new OAuth client.
![img.png](.github/img/create-oauth-client.png)
Then select "Web application" as the application type, enter a name and add an authorized redirection
uri `https://<your-domain>/contao/login_sso/redirect`.
After you've created the OAuth client, you can copy the client id and client secret into a `.env.local` file in the
root folder of your Contao installation.

**Don't forget to set the usertype to "intern" in the OAuth consent screen or otherwise any google user could log in!**
![img.png](.github/img/change-to-intern-users-only.png)

After you've configured the environment variables, you can log in using the new login
url (`https://<your-domain>/contao/login_sso`).

## Integrating the login into the be_login page

If you don't want a different login url you can also overwrite the `be_login.html5` template.
For this, you can create a `be_login.html5` file under your `templates` folder and add the following snippet (replacing):
```php
<?php $this->extend('be_login'); ?>

<?php $this->block('head'); ?>
<?php $this->parent(); ?>
<script src="https://accounts.google.com/gsi/client" async></script>
<?php $this->endblock(); ?>

<?php $this->block('container'); ?>
<?php $this->parent(); ?>
<div id="g_id_onload"
     data-client_id="<YOUR_CLIENT_ID>"
     data-context="signin"
     data-login_uri="https://<your-domain>/contao/login_sso/redirect"
     data-auto_select="false"
     data-close_on_tap_outside="false"
     data-itp_support="true">
</div>
<?php $this->endblock(); ?>
```

# References
This bundle was inspired by https://github.com/BROCKHAUS-AG/contao-microsoft-sso-bundle and uses a similar flow.  
Documentation to google login: https://developers.google.com/identity/authentication
