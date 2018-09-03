<?php

namespace primus852\SimpleCrypt;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Key;

class SimpleCrypt
{

    private $enc_method;
    private $s_key;
    private $s_iv;
    private $ascii;

    /**
     * SimpleCrypt constructor.
     * @param string $s_key
     * @param string $s_iv
     */
    public function __construct(string $s_key = 'salt', string $s_iv = 'iv')
    {

        $this->enc_method = 'AES-256-CBC';
        $this->s_key = hash('sha256', $s_key);
        $this->s_iv = substr(hash('sha256', $s_iv), 0, 16);

    }

    /**
     * @param string $string
     * @return string
     */
    public function encrypt(string $string)
    {

        return base64_encode(openssl_encrypt($string, $this->enc_method, $this->s_key, 0, $this->s_iv));

    }

    /**
     * @param string $string
     * @return string
     */
    public function decrypt(string $string)
    {

        return openssl_decrypt(base64_decode($string), $this->enc_method, $this->s_key, 0, $this->s_iv);

    }

    /**
     * @param string $plain
     * @param string $ascii
     * @return string
     * @throws CryptoException
     */
    public static function encCipher(string $plain, string $ascii){

        try {
            return Crypto::encrypt($plain, Key::loadFromAsciiSafeString($ascii), false);
        } catch (CryptoException $e) {
            throw new CryptoException($e->getMessage());
        }

    }

    /**
     * @param string $cipher
     * @param string $ascii
     * @return string
     * @throws CryptoException
     */
    public static function decCipher(string $cipher, string $ascii){

        try {
            return Crypto::decrypt($cipher, Key::loadFromAsciiSafeString($ascii), false);
        } catch (CryptoException $e) {
            throw new CryptoException($e->getMessage());
        }

    }

    /**
     * @param string $string
     * @param string $key
     * @param string $iv
     * @param string $method
     * @return string
     */
    public static function enc(string $string, string $key = 'salt', string $iv = 'iv', string $method = 'AES-256-CBC')
    {
        return base64_encode(openssl_encrypt($string, $method, $key, 0, $iv));
    }

    /**
     * @param string $string
     * @param string $key
     * @param string $iv
     * @param string $method
     * @return string
     */
    public static function dec(string $string, string $key = 'salt', string $iv = 'iv', string $method = 'AES-256-CBC'){
        return openssl_decrypt(base64_decode($string), $method, $key, 0, $iv);
    }

    /**
     * @return string
     */
    public function getEncMethod()
    {
        return $this->enc_method;
    }

    /**
     * @param string $enc_method
     */
    public function setEncMethod($enc_method)
    {
        $this->enc_method = $enc_method;
    }

    /**
     * @return string
     */
    public function getSKey()
    {
        return $this->s_key;
    }

    /**
     * @param string $s_key
     */
    public function setSKey($s_key)
    {
        $this->s_key = $s_key;
    }

    /**
     * @return bool|string
     */
    public function getSIv()
    {
        return $this->s_iv;
    }

    /**
     * @param bool|string $s_iv
     */
    public function setSIv($s_iv)
    {
        $this->s_iv = $s_iv;
    }


}