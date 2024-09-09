<?php

namespace MLukman\SecurityHelperBundle\Util;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use ReCaptcha\ReCaptcha;
use ReCaptcha\RequestMethod\Post;
use ReCaptcha\RequestParameters;
use ReCaptcha\Response;

/**
 * Customized ReCaptcha wrapper that fails silently if there is connection timeout
 * when connecting to Google ReCaptcha server.
 */
class ReCaptchaUtil
{

    private ?string $sitekey = null;
    private ?string $secretkey = null;
    private array $captchaResponses = [];

    public function __construct()
    {
        $this->sitekey = $_ENV['GOOGLE_RECAPTCHA_SITE_KEY'] ?? null;
        $this->secretkey = $_ENV['GOOGLE_RECAPTCHA_SECRET'] ?? null;
    }

    public function isEnabled(): bool
    {
        return !empty($this->sitekey) && !empty($this->secretkey);
    }

    public function getSiteKey(): ?string
    {
        return $this->sitekey;
    }

    public function verify(string $recaptcha_response): Response
    {
        $recaptcha = new ReCaptcha($this->secretkey, new class extends Post {

                    public function submit(RequestParameters $params)
                    {
                        try {
                            $client = new Client();
                            $response = $client->post(ReCaptcha::SITE_VERIFY_URL, [
                                'headers' => [
                                    'Content-type' => 'application/x-www-form-urlencoded\r\n',
                                ],
                                'body' => $params->toQueryString(),
                                'connect_timeout' => 10,
                            ]);

                            if ($response !== false) {
                                return $response->getBody();
                            }

                            return '{"success": false, "error-codes": ["' . ReCaptcha::E_CONNECTION_FAILED . '"]}';
                        } catch (ConnectException $ex) {
                            return '{"success": true, "error-codes": ["connect-timeout"]}';
                        }
                    }
                });

        return $this->captchaResponses[$recaptcha_response] ??
                ($this->captchaResponses[$recaptcha_response] = $recaptcha->verify($recaptcha_response));
    }
}
