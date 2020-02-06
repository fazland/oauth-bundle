<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Encryption;

use Fazland\OAuthBundle\Encryption\Jwt;
use Fazland\OAuthBundle\Enum\SignatureAlgorithm;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    /**
     * @var Jwt
     */
    private $encoder;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->encoder = new Jwt();
    }

    public function testEncode(): void
    {
        $key = '-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANAG2ht/Htaj8Xo0
CLpUaxa7YaxdvrzGOH6ZLpyEB9VeHJq2yyvGNP7RW41dNJpwOh26SitGqplf81GA
aBFapxUvxlvEyZ+0R0JPnUbA96oGDhCLxOZ+cqZWaEflCXXaeNDc8Hft9JtU+uS+
FCX1qq81NERfnlfkCSwrcwzqzAEtAgMBAAECgYEAumNpSPm9R9PcqQG2UD0TNmru
OOJF5B42wDe/67zgx+xq9LSTlcUh9q7euOqqFzY23CvuCJhogsPV31CN7f6rdFDj
rv6h8vdFTA8m7bteFMz5wc8xD9tp1tmZdZIBHZCCBK9blhQWK3uZOcEhzuN8ucnb
zM8tQfIauxTZuqK4noECQQD9Ur/YksKfom3K62oL6UzeAb4B4+CWoKPdHovmh2lj
fBML2jYbiOXMMmlJ/FbpN0mr9GU6kLsRXN2lc2XoDN9zAkEA0jmS2DDJt+dclyqw
5CipJBQSC9HSF9bQGIlskDJSJIn45J355/3HCPjMiHsR2cIXhYczo8DyfA1ZDugB
/IY03wJAMEc2/MVrhhTkq8mV2lNKLP1UAvQ090ACOr/5laO0+BrLXnTl3vWGJhZt
boZC4guBZN4c9L5kiHiUXVXS1Biv9QJBALNogxORf3U9M92mh1QQB1lM76G6rSu/
HdTy4v2klEmungStdWsxPz0+537KWQ+X/u7r1Xw43DhWQ9zez2MtPc0CQF1nJKfU
33rZNmgzSpB0VUFhtApsfRPNp5k3jLZL8IV+UWULvmOOm6kVs+hQYPPSM5crlEOw
09NyArd5+kkcGiY=
-----END PRIVATE KEY-----
';

        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjRlNzIwMjNmYmRmZTViMTFkODZhNDYzMDNiMTY3MzVjYTkxNjg1Y2MiLCJqdGkiOiI0ZTcyMDIzZmJkZmU1YjExZDg2YTQ2MzAzYjE2NzM1Y2E5MTY4NWNjIiwiaXNzIjoiYXBpLmJlY3Jvd2R5LmxvY2FsIiwiYXVkIjoiYXNhc2QiLCJzdWIiOjEsImV4cCI6MTQ1ODUxNTExNCwiaWF0IjoxNDU4NTExNTE0LCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwic2NvcGUiOiJyZWFkIn0.ZJ_6BDUk-CTHCP4VSOUYzPXfCQxKvgaerkVXZG-38d7nbc8fs2906O3NU6DW7imU7B-gTK4hlqiwe3YNLMTqmxrETJQV9vwIGivp3A8_sTFr5AQQCiXwK_ib2lGj2_LE6D8fsuSlmA1KRRAYrOW5Iz8FGdo0ukmfhCV88czC2ak';

        $result = $this->encoder->encode([
            'id' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'jti' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'iss' => 'api.becrowdy.local',
            'aud' => 'asasd',
            'sub' => 1,
            'exp' => 1458515114,
            'iat' => 1458511514,
            'token_type' => 'bearer',
            'scope' => 'read',
        ], $key, SignatureAlgorithm::RS256);

        self::assertEquals($expected, $result);
    }

    public function testDecodeWithInvalidJwt(): void
    {
        self::assertFalse($this->encoder->decode('test'));
    }

    public function testDecode(): void
    {
        $clientKey = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQBtobfx7Wo/F6NAi6VGsWu2Gs
Xb68xjh+mS6chAfVXhyatssrxjT+0VuNXTSacDodukorRqqZX/NRgGgRWqcVL8Zb
xMmftEdCT51GwPeqBg4Qi8TmfnKmVmhH5Ql12njQ3PB37fSbVPrkvhQl9aqvNTRE
X55X5AksK3MM6swBLQIDAQAB
-----END PUBLIC KEY-----
';
        $params = [
            'id' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'jti' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'iss' => 'api.becrowdy.local',
            'aud' => 'asasd',
            'sub' => 1,
            'exp' => 1458515114,
            'iat' => 1458511514,
            'token_type' => 'bearer',
            'scope' => 'read',
        ];
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjRlNzIwMjNmYmRmZTViMTFkODZhNDYzMDNiMTY3MzVjYTkxNjg1Y2MiLCJqdGkiOiI0ZTcyMDIzZmJkZmU1YjExZDg2YTQ2MzAzYjE2NzM1Y2E5MTY4NWNjIiwiaXNzIjoiYXBpLmJlY3Jvd2R5LmxvY2FsIiwiYXVkIjoiYXNhc2QiLCJzdWIiOjEsImV4cCI6MTQ1ODUxNTExNCwiaWF0IjoxNDU4NTExNTE0LCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwic2NvcGUiOiJyZWFkIn0.ZJ_6BDUk-CTHCP4VSOUYzPXfCQxKvgaerkVXZG-38d7nbc8fs2906O3NU6DW7imU7B-gTK4hlqiwe3YNLMTqmxrETJQV9vwIGivp3A8_sTFr5AQQCiXwK_ib2lGj2_LE6D8fsuSlmA1KRRAYrOW5Iz8FGdo0ukmfhCV88czC2ak';

        $result = $this->encoder->decode($jwt, null, false);
        self::assertEquals($params, $result);

        $result = $this->encoder->decode($jwt, $clientKey, [SignatureAlgorithm::RS256]);
        self::assertEquals($params, $result);

        self::assertFalse($this->encoder->decode($jwt, $clientKey, ['ASD']));

        $jwt = 'eyJhbGciOiIiLCJ0eXBlIjoiSldUIn0.eyJpZCI6IjRlNzIwMjNmYmRmZTViMTFkODZhNDYzMDNiMTY3MzVjYTkxNjg1Y2MiLCJqdGkiOiI0ZTcyMDIzZmJkZmU1YjExZDg2YTQ2MzAzYjE2NzM1Y2E5MTY4NWNjIiwiaXNzIjoiYXBpLmJlY3Jvd2R5LmxvY2FsIiwiYXVkIjoiYXNhc2QiLCJzdWIiOjEsImV4cCI6MTQ1ODUxNTExNCwiaWF0IjoxNDU4NTExNTE0LCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwic2NvcGUiOiJyZWFkIn0.';
        self::assertFalse($this->encoder->decode($jwt, $clientKey, [SignatureAlgorithm::RS256]));

        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJpZCI6IjRlNzIwMjNmYmRmZTViMTFkODZhNDYzMDNiMTY3MzVjYTkxNjg1Y2MiLCJqdGkiOiI0ZTcyMDIzZmJkZmU1YjExZDg2YTQ2MzAzYjE2NzM1Y2E5MTY4NWNjIiwiaXNzIjoiYXBpLmJlY3Jvd2R5LmxvY2FsIiwiYXVkIjoiYXNhc2QiLCJzdWIiOjEsImV4cCI6MTQ1ODUxNTExNCwiaWF0IjoxNDU4NTExNTE0LCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwic2NvcGUiOiJyZWFkIn0.ZJ_6BDUk-CTHCP4VSOUYzPXfCQxKvgaerkVXZG-38d7nbc8fs2906O3NU6DW7imU7B-gTK4hlqiwe3YNLMTqmxrETJQV9vwIGivp3A8_sTFr5AQQCiXwK_ib2lGj2_LE6D8fsuSlmA1KRRAYrOW5Iz8FGdo0ukmfhCV88czC2ak';
        self::assertFalse($this->encoder->decode($jwt, $clientKey));
    }

    public function testEcdsaSignatures()
    {
        $privateKey = <<<EOF
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIOyZuXXez9GWLXkNvFqryYoadZTHWCnq9wpTXNFntwKGoAcGBSuBBAAK
oUQDQgAEVOTH/lI3+zNeN78ZH1nvj3UTQsTKqSp+ct+0FacKo0erzPsl7a1IGHJn
lxs5VpIKMDgjAc3YbKz8WLBn7Yd9SQ==
-----END EC PRIVATE KEY-----
EOF;

        $publicKey = <<<EOF
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEVOTH/lI3+zNeN78ZH1nvj3UTQsTKqSp+
ct+0FacKo0erzPsl7a1IGHJnlxs5VpIKMDgjAc3YbKz8WLBn7Yd9SQ==
-----END PUBLIC KEY-----
EOF;

        $params = [
            'id' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'jti' => '4e72023fbdfe5b11d86a46303b16735ca91685cc',
            'iss' => 'api.becrowdy.local',
            'aud' => 'asasd',
            'sub' => 1,
            'exp' => 1458515114,
            'iat' => 1458511514,
            'token_type' => 'bearer',
            'scope' => 'read',
        ];

        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjRlNzIwMjNmYmRmZTViMTFkODZhNDYzMDNiMTY3MzVjYTkxNjg1Y2MiLCJqdGkiOiI0ZTcyMDIzZmJkZmU1YjExZDg2YTQ2MzAzYjE2NzM1Y2E5MTY4NWNjIiwiaXNzIjoiYXBpLmJlY3Jvd2R5LmxvY2FsIiwiYXVkIjoiYXNhc2QiLCJzdWIiOjEsImV4cCI6MTQ1ODUxNTExNCwiaWF0IjoxNDU4NTExNTE0LCJ0b2tlbl90eXBlIjoiYmVhcmVyIiwic2NvcGUiOiJyZWFkIn0';

        $result = $this->encoder->encode($params, $privateKey, SignatureAlgorithm::ES256());
        self::assertStringStartsWith($jwt, $result);
        self::assertEquals($params, $this->encoder->decode($result, $publicKey));
    }
}
