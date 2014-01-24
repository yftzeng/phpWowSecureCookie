<?php
/**
 * Wow Secure Cookie Manager
 *
 * PHP version 5
 *
 * @category Wow
 * @package  WowSecureCookie
 * @author   Matthieu Huguet <matthieu@huguet.eu>
 * @author   Yi-Feng Tzeng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT License
 * @link     http://blog.gcos.me/
 */

namespace Wow\Security;

/**
 * Wow Secure Cookie Manager class
 *
 * @category Wow
 * @package  WowSecureCookie
 * @author   Matthieu Huguet <matthieu@huguet.eu>
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT License
 * @link     http://blog.gcos.me/
 */

class WowSecureCookie
{

    /**
     * Server secret key
     * @var string
     */
    protected $secret = '';

    /**
     * Encrypt/Decrypt IV, only works if PHP version >= 5.3.3
     * Must be 16 bytes long
     * @var string
     */
    protected $iv = '1234567890123456';

    /**
     * Cryptographic algorithm used to encrypt cookies data
     * Ref: http://www.php.net/manual/en/function.openssl-get-cipher-methods.php
     * @var object
     */
    protected $algorithm = 'AES-256-CFB';

    /**
     * Salt for Hash algorithm used to hash cookies data
     * @var string
     */
    protected $salt = 'badbadguy';

    /**
     * Default cookie expired time
     * 86400   = 24 hour = 1 day
     * 2592000 = 30 day
     * @var int
     */
    protected $expired_time = 2592000;

    /**
     * Hash algorithm used to hash cookies data
     * Ref: http://www.php.net/manual/en/function.hash-algos.php
     * @var string
     */
    protected $hash = 'sha1';

    /**
     * Secure Cookie level
     * 1: secureValue = username|expire|value|HMAC(user|expire|value,k)
     * 2: secureValue =
     *    username|expire|base64((value)k,expire)|HMAC(user|expire|value,k)
     * 3: secureValue = encrypt(value)
     * 4: secureValue = username|expire|encrypt(value)|HMAC(user|expire|value,k)
     * @var bool
     */
    protected $secure_level = 3;

    /**
     * Enable SSL support
     * @var bool
     */
    protected $ssl = false;

    /**
     * @param string $secret server's secret key
     * @param array  $config config array
     *
     * @comment Constructor
     *
     * Initialize cookie manager and mcrypt module.
     *
     * @return void
     */
    public function __construct($secret, $config = null)
    {
        if (empty($secret)) {
            throw new Exception('You must provide a secret key');
        }

        $this->secret = $secret;

        if ($config !== null && !is_array($config)) {
            throw new Exception('Config must be an array');
        }

        if (is_array($config)) {
            if (isset($config['algorithm'])) {
                $this->algorithm = $config['algorithm'];
            }
            if (isset($config['iv'])) {
                $this->iv = $config['iv'];
            }
            if (isset($config['salt'])) {
                $this->salt = $config['salt'];
            }
            if (isset($config['default_expire'])) {
                $this->expired_time = $config['default_expire'];
            }
            if (isset($config['hash'])) {
                $this->hash = $config['hash'];
            }
            if (isset($config['secure_level'])) {
                $this->secure_level = $config['secure_level'];
            }
            if (isset($config['enable_ssl'])) {
                $this->ssl = $config['enable_ssl'];
            }
        }

        if (in_array($this->algorithm, openssl_get_cipher_methods()) === false) {
            throw new Exception('Error while loading mcrypt module');
        }
    }

    /**
     * Get the secure level mode
     *
     * @return bool true if cookie data encryption is enabled, or false if it isn't
     */
    public function getSecureLevel()
    {
        return $this->secure_level;
    }

    /**
     * @param bool $enable true to enable, false to disable
     *
     * @comment Set the secure level mode
     * Enable or disable cookie data encryption
     *
     * @return mixed
     */
    public function setSecureLevel($enable)
    {
        $this->secure_level = $enable;
        return $this;
    }

    /**
     * @comment Get the SSL status (enabled or disabled?)
     *
     * @return bool true if SSL support is enabled, or false if it isn't
     *
     */
    public function getSSL()
    {
        return $this->ssl;
    }

    /**
     * @param bool $enable true to enable, false to disable
     *
     * @comment Enable SSL support (not enabled by default)
     * pro: protect against replay attack
     * con: cookie's lifetime is limited to SSL session's lifetime
     *
     * @return mixed
     */
    public function setSSL($enable)
    {
        $this->ssl = $enable;
        return $this;
    }

    /**
     * @param string $username username
     *
     * @comment Hash username for more secure
     *
     * @return string
     */
    public function doHash($username)
    {
        if ($this->hash === 'sha1') {
            return sha1($username . $this->salt);
        } elseif ($this->hash === 'md5') {
            return md5($username . $this->salt);
        } else {
            return sha1($username . $this->salt);
        }
    }

    /**
     * @param string  $cookiename cookie name
     * @param string  $value      cookie value
     * @param string  $username   user name (or ID)
     * @param integer $expire     expiration time
     * @param string  $path       cookie path
     * @param string  $domain     cookie domain
     * @param bool    $secure     when true, send cookie only on secure connection
     * @param bool    $httponly   when true the cookie will be made accessible only
     *                            through the HTTP protocol
     *
     * @comment Send a secure cookie
     *
     * @return mixed
     */
    public function setCookie(
        $cookiename, $value, $username = null, $expire = null, $path = '',
        $domain = '', $secure = false, $httponly = null
    ) {
        if ($this->secure_level !==3 ) {
            if (is_null($username)) {
                throw new Exception('You must provide $username argument');
            }
        }
        $expire = is_null($expire) ? time() + $this->expired_time : $expire;
        if ($this->secure_level === 2) {
            $value = base64_encode($value . ',' . $expire);
        }
        if ($this->secure_level === 3) {
            $secureValue = $this->encrypt($value, $this->secret);
        } else {
            $secureValue = $this->secureCookieHashValue(
                $value, $this->doHash($username), $expire
            );
        }
        $this->setClassicCookie(
            $cookiename, $secureValue, $expire, $path, $domain, $secure, $httponly
        );
    }

    /**
     * @param string $cookiename cookie name
     * @param string $path       cookie path
     * @param string $domain     cookie domain
     * @param bool   $secure     when true, send cookie only on a secure connection
     * @param bool   $httponly   when true the cookie will be made accessible only
     *                           through the HTTP protocol
     *
     * @comment Delete a cookie
     *
     * @return void
     */
    public function deleteCookie(
        $cookiename, $path = '/', $domain = '', $secure = false, $httponly = null
    ) {
        // delete cookie only once
        if (isset($this->deleted)) {
            return;
        } else {
            $this->deleted = true;
        }
        /* 1980-01-01 */
        $expire = 315554400;
        setcookie($cookiename, '', $expire, $path, $domain, $secure, $httponly);
    }

    /**
     * @param string $cookiename      cookie name
     * @param bool   $deleteIfInvalid destroy the cookie if invalid
     *
     * @comment Get a secure cookie value
     *
     * Verify the integrity of cookie data and decrypt it.
     * If the cookie is invalid, it can be automatically destroyed
     * (default behaviour)
     *
     * @return mixed
     */
    public function getCookie($cookiename, $deleteIfInvalid = true)
    {
        if ($this->cookieExists($cookiename)) {
            if ($this->secure_level === 3) {
                return $this->decrypt($_COOKIE[$cookiename], $this->secret);
            }
            $cookieValues = explode('|', $_COOKIE[$cookiename]);
            if ((count($cookieValues) === 4)
                && ($cookieValues[1] == 0 || $cookieValues[1] >= time())
            ) {
                $key = hash_hmac(
                    $this->hash, $cookieValues[0].$cookieValues[1], $this->secret
                );
                $cookieData = $cookieValues[2];
                if ($this->secure_level === 1 || $this->secure_level === 2) {
                    $data = $cookieData;
                } elseif ($this->secure_level === 4) {
                    $data = $this->decrypt($cookieData, $key, md5($cookieValues[1]));
                }

                if ($this->_ssl && isset($_SERVER['SSL_SESSION_ID'])) {
                    $verifKey = hash_hmac(
                        $this->hash,
                        $cookieValues[0].$cookieValues[1].$data.
                        $_SERVER['SSL_SESSION_ID'],
                        $key
                    );
                } else {
                    $verifKey = hash_hmac(
                        $this->hash, $cookieValues[0].$cookieValues[1].$data, $key
                    );
                }
                if ($verifKey === $cookieValues[3]) {
                    if ($this->secure_level === 2) {
                        $data = base64_decode($cookieData);
                        $data = explode(',', $data)[0];
                    }
                    return $data;
                }
            }
        }
        if ($deleteIfInvalid) {
            $this->deleteCookie($cookiename);
        }
        return false;
    }

    /**
     * @param string $cookiename      cookie name
     * @param bool   $deleteIfInvalid destroy the cookie if invalid
     *
     * @comment Get a classic (unsecure) cookie value
     *
     * @return mixed
     */
    public function getClassicCookieValue($cookiename, $deleteIfInvalid = true)
    {
        if ($this->cookieExists($cookiename)) {
            return $_COOKIE[$cookiename];
        }
        if ($deleteIfInvalid) {
            $this->deleteCookie($cookiename);
        }
        return false;
    }

    /**
     * @param string  $cookiename cookie name
     * @param string  $value      cookie value
     * @param integer $expire     expiration time
     * @param string  $path       cookie path
     * @param string  $domain     cookie domain
     * @param bool    $secure     when true, send cookie only in secure connection
     * @param bool    $httponly   when true the cookie will be made accessible
     *                            only through the HTTP protocol
     *
     * @comment Send a classic (unsecure) cookie
     *
     * @return void
     */
    public function setClassicCookie(
        $cookiename, $value, $expire = 0, $path = '', $domain = '',
        $secure = false, $httponly = null
    ) {
        /* httponly option is only available for PHP version >= 5.2 */
        if ($httponly !== null
            && (!defined('PHP_VERSION_ID')
            || PHP_VERSION_ID >= 50200)
        ) {

            setcookie(
                $cookiename, $value, $expire, $path, $domain, $secure, $httponly
            );
        } else {
            setcookie($cookiename, $value, $expire, $path, $domain, $secure);
        }
    }

    /**
     * @param string $cookiename the cookie's name
     *
     * @comment Verify if a cookie exists
     *
     * @return bool true if cookie exist, or false if not
     */
    public function cookieExists($cookiename)
    {
        return isset($_COOKIE[$cookiename]);
    }

    /**
     * @param string  $value    unsecure value
     * @param string  $username user name (or ID)
     * @param integer $expire   expiration time
     *
     * @comment Secure a hash cookie value
     *
     * The initial value is transformed with this protocol :
     *
     *  secureValue =
     *      username|expire|base64((value)k,expire)|HMAC(user|expire|value,k)
     *  where k = HMAC(user|expire, sk)
     *  and sk is server's secret key
     *  (value)k,md5(expire) is the result an cryptographic function (ex: AES256)
     *  on "value" with key k and initialisation vector = md5(expire)
     *
     * @return string secured value
    */

    protected function secureCookieHashValue($value, $username, $expire)
    {
        $key = hash_hmac($this->hash, $username.$expire, $this->secret);
        if ($this->secure_level === 4) {
            $encryptedValue = $this->encrypt($value, $key, md5($expire));
        } else {
            $encryptedValue = $value;
        }
        if ($this->_ssl && isset($_SERVER['SSL_SESSION_ID'])) {
            $verifKey = hash_hmac(
                $this->hash,
                $username . $expire . $value . $_SERVER['SSL_SESSION_ID'],
                $key
            );
        } else {
            $verifKey = hash_hmac($this->hash, $username . $expire . $value, $key);
        }
        $result = array($username, $expire, $encryptedValue, $verifKey);
        return implode('|', $result);
    }

    /**
     * @param string $data data to crypt
     * @param string $key  secret key
     *
     * @comment Encrypt given data with given key and a given initialisation vector
     *
     * @return string encrypted data
     */
    protected function encrypt($data, $key)
    {
        /* If PHP version >= 5.3.3 */
        if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID >= 50303) {
            $res = openssl_encrypt(
                $data, $this->algorithm, $key, false, $this->iv
            );
        } else {
            $res = openssl_encrypt($data, $this->algorithm, $key, false);
        }
        return $res;
    }

    /**
     * @param string $data data to crypt
     * @param string $key  secret key
     *
     * @comment Decrypt given data with given key and a given initialisation vector
     *
     * @return string encrypted data
     */
    protected function decrypt($data, $key)
    {
        /* If PHP version >= 5.3.3 */
        if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID >= 50303) {
            $res = openssl_decrypt(
                $data, $this->algorithm, $key, false, $this->iv
            );
        } else {
            $res = openssl_decrypt($data, $this->algorithm, $key, false);
        }
        return $res;
    }

    /**
     * @param string $data set given secret
     *
     * @comment set secret
     *
     * @return void
     */
    public function setSecret($data)
    {
        $this->secret = $data;
    }

    /**
     * @param string $data set given iv
     *
     * @comment set iv
     *
     * @return void
     */
    public function setIv($data)
    {
        $this->iv = $data;
    }

    /**
     * @param string $data set given encryption algorithm
     *
     * @comment set encryption algorithm
     *
     * @return void
     */
    public function setAlgorithm($data)
    {
        $this->algorithm = $data;
    }

    /**
     * @param string $data set salt
     *
     * @comment set salt
     *
     * @return void
     */
    public function setSalt($data)
    {
        $this->salt = $data;
    }

    /**
     * @param string $data expired time
     *
     * @comment set expired time
     *
     * @return void
     */
    public function setExpiredTime($data)
    {
        $this->expired_time = $data;
    }

    /**
     * @param string $data data to hash
     *
     * @comment hash a given data
     *
     * @return void
     */
    public function setHash($data)
    {
        $this->hash($data);
    }
}
