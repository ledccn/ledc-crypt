<?php

namespace Ledc\Crypt;

use ErrorException;
use InvalidArgumentException;
use Throwable;

/**
 * 对称加密解密与加签验签
 */
readonly class AesCrypt
{
    /**
     * 构造函数
     * @param string $key 对称密钥
     * @param string $cipher 对称算法
     * @param string $hmac_algo 散列算法
     * @param int $expires_in 数据包有效时间（单位秒）
     */
    public function __construct(
        protected string $key,
        protected string $cipher = 'aes-128-cbc',
        protected string $hmac_algo = 'sha256',
        protected int    $expires_in = 30
    )
    {
        if (!in_array($this->hmac_algo, hash_hmac_algos(), true)) {
            throw new InvalidArgumentException('无效的散列算法');
        }
    }

    /**
     * 对称加密
     * @param array $data 数据包
     * @return array
     * @throws ErrorException
     */
    public function encrypt(array $data): array
    {
        try {
            $aesKey = $this->getKey();
            $cipher = $this->getCipher();
            $ivLen = openssl_cipher_iv_length($cipher);
            $iv = openssl_random_pseudo_bytes($ivLen);
            $noncestr = bin2hex(openssl_random_pseudo_bytes(8));
            $timestamp = time();

            // 附加数据
            $addReq = ['_noncestr' => $noncestr];
            $realData = array_merge($addReq, $data);
            $plaintext = json_encode($realData);

            // 加密
            $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $aesKey, OPENSSL_RAW_DATA, $iv);
            if (false === $ciphertext_raw) {
                throw new InvalidArgumentException(openssl_error_string() ?: 'Encrypt AES CBC error.');
            }

            $payload = base64_encode(json_encode([
                'iv' => base64_encode($iv),
                'data' => base64_encode($ciphertext_raw),
                'timestamp' => $timestamp,
                'expires_in' => $this->getExpiresIn()
            ]));

            // 签名
            $signature = hash_hmac($this->getHmacAlgo(), $payload, $aesKey);

            return compact('payload', 'signature');
        } catch (Throwable $throwable) {
            throw new ErrorException($throwable->getMessage(), $throwable->getCode());
        }
    }

    /**
     * 对称解密
     * @param string $payload 有效载荷
     * @param string $signature 签名
     * @return array 数据包
     * @throws ErrorException
     */
    public function decrypt(string $payload, string $signature): array
    {
        try {
            $aesKey = $this->getKey();
            $cipher = $this->getCipher();

            // 验签
            $hmac = hash_hmac($this->getHmacAlgo(), $payload, $aesKey);
            if (hash_equals($signature, $hmac)) {
                $_payload = json_decode(base64_decode($payload), true);
                $iv = base64_decode($_payload['iv']);
                $ciphertext_raw = base64_decode($_payload['data']);
                $timestamp = $_payload['timestamp'];
                $expires_in = $_payload['expires_in'];

                // 验证时间戳
                if ($expires_in < abs(time() - $timestamp)) {
                    throw new InvalidArgumentException('时间戳验证失败，误差超过' . $expires_in . '秒');
                }

                // 解密
                $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $aesKey, OPENSSL_RAW_DATA, $iv);
                if ($original_plaintext === false) {
                    throw new InvalidArgumentException(openssl_error_string() ?: 'Decrypt AES CBC error.');
                }

                return json_decode($original_plaintext, true);
            }

            throw new InvalidArgumentException('签名验证失败');
        } catch (Throwable $throwable) {
            throw new ErrorException($throwable->getMessage(), $throwable->getCode());
        }
    }

    /**
     * 获取对称密钥
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * 获取对称算法
     * @return string
     */
    public function getCipher(): string
    {
        return $this->cipher;
    }

    /**
     * 获取数据包有效时间
     * @return int
     */
    public function getExpiresIn(): int
    {
        return $this->expires_in;
    }

    /**
     * 获取散列算法
     * @return string
     */
    public function getHmacAlgo(): string
    {
        return $this->hmac_algo;
    }
}
