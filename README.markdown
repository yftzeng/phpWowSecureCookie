# phpWowSecurityCookie

Secure our cookie.

## Requirement

PHP 5.3+

## Usage

### Standalone WowLog library

```
include '/src/Wow/Security/WowSecurityCookie.php';

$secretKey = 'Cei4Wai4ohcoo3daeHooFiek5Nah3Eet';
$config    = array('high_confidentiality' => false);
$manager   = new WowSecCookie($secretKey, $config);

# set cookie
$expire = time() + 86400;
$manager->setCookie('cookieName', 'value', 'username', $expire);

# get cookie
$value = $manager->getCookie('cookieName');
echo $value;
```

### Work with Composer

#### Edit `composer.json`

```
{
    "require": {
        "yftzeng/wow-security-cookie": "dev-master"
    }
}
```

#### Update composer

```
$ php composer.phar update
```

#### Sample code
```
include 'vendor/autoload.php';

$secretKey = 'Cei4Wai4ohcoo3daeHooFiek5Nah3Eet';
$config    = array('high_confidentiality' => false);
$manager   = new WowSecCookie($secretKey, $config);

# set cookie
$expire = time() + 86400;
$manager->setCookie('cookieName', 'value', 'username', $expire);

# get cookie
$value = $manager->getCookie('cookieName');
echo $value;
```

## License

the MIT License
