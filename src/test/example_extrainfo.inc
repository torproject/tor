static const char EX_EI_MINIMAL[] =
  "extra-info bob 3E1B2DC141F2B7C6A0F3C4ED9A14A9C35762E24B\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "K5GAkVjpUlofL78NIOE1VDxFn8yYbHK50rVuZG2HxqG/727bon+uMprv4MHjfDcP\n"
  "V3l9u1uUdGiUPOl8j+hRNw4z/ODeCj/24r2+L32MTjyfUhK49Ld2IlK9iZKlgKYi\n"
  "zyoatxdAjU8Xc5WPX692HO4/R9CGLsUfYcEEFU2R3EA=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_MINIMAL_FP[] = "3E1B2DC141F2B7C6A0F3C4ED9A14A9C35762E24B";
static const char EX_EI_MINIMAL_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBALSppIF3t3wOAm4fzxRvK+q/wh1gGAWwS0JEn8d+c/x+rt1oQabGkqsB\n"
  "GU6rz1z1AN02W0P2+EcyJQVBjGR3gHQNoDGx0KIdnr3caGAw3XmQXrJLPaViEk28\n"
  "RJMxx6umpP27YKSyEMHgVTDXblKImT0mE7fVOx8tD0EWRYazmp4NAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_MAXIMAL[] =
  "extra-info bob FF8248FE780A7236D3FA5D62DEA642055135F942\n"
  "published 2014-10-05 20:07:00\n"
  "opt foobarbaz\n"
  "read-history 900 1,2,3\n"
  "write-history 900 1,2,3\n"
  "dirreq-v2-ips 1\n"
  "dirreq-v3-ips 100\n"
  "dirreq-v3-reqs blahblah\n"
  "dirreq-v2-share blahblah\n"
  "dirreq-v3-share blahblah\n"
  "dirreq-v2-resp djfkdj\n"
  "dirreq-v3-resp djfkdj\n"
  "dirreq-v2-direct-dl djfkdj\n"
  "dirreq-v3-direct-dl djfkdj\n"
  "dirreq-v2-tunneled-dl djfkdj\n"
  "dirreq-v3-tunneled-dl djfkdj\n"
  "dirreq-stats-end foobar\n"
  "entry-ips jfsdfds\n"
  "entry-stats-end ksdflkjfdkf\n"
  "cell-stats-end FOO\n"
  "cell-processed-cells FOO\n"
  "cell-queued-cells FOO\n"
  "cell-time-in-queue FOO\n"
  "cell-circuits-per-decile FOO\n"
  "exit-stats-end FOO\n"
  "exit-kibibytes-written FOO\n"
  "exit-kibibytes-read FOO\n"
  "exit-streams-opened FOO\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "ZO79bLlWVNIruCnWW9duDcOKydPWbL5DfrpUv5IRLF4MMFoacMUdJPDUs9e+wY2C\n"
  "zndHe6i2JK7yKJj+uCOSC8cx61OLG+kVxMLJ/qhA4H5thrYb+GpzMKwbHzQc3PTH\n"
  "zHRzj041iWXTL7/DMaQlpJOBoac/wTSIKzoV2B00jBw=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_MAXIMAL_FP[] = "FF8248FE780A7236D3FA5D62DEA642055135F942";
static const char EX_EI_MAXIMAL_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBANSpkYhHUW1EqodY4d3JRbvEM1vjjR/vEE8gjONiJ5t2Sten53jzt8bh\n"
  "8/VJn7pQGs8zR5CIxCw4P68xMtZJJedS3hhjqubheOE/yW1DtpkiCf+zVEaLpeA8\n"
  "fYQChkRICnR/BZd4W9bbohLVII5ym2PaJt2ihB3FeVZIsGXm4wxhAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_BAD_SIG1[] =
  "extra-info bob 3E1B2DC141F2B7C6A0F3C4ED9A14A9C35762E24B\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "K5GAkVjpUlofL78NIOE1VDxFn8yYbHK50rVuZG2HxqG/727bon+uMprv4MHjfDcP\n"
  "V3l9u1uUdGiUPOl8j+hXXw4z/ODeCj/24r2+L32MTjyfUhK49Ld2IlK9iZKlgKYi\n"
  "zyoatxdAjU8Xc5WPX692HO4/R9CGLsUfYcEEFU2R3EA=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_SIG2[] =
  "extra-info bob 3E1B2DC141F2B7C6A0F3C4ED9A14A9C35762E24B\n"
  "published 2014-10-06 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "K5GAkVjpUlofL78NIOE1VDxFn8yYbHK50rVuZG2HxqG/727bon+uMprv4MHjfDcP\n"
  "V3l9u1uUdGiUPOl8j+hRNw4z/ODeCj/24r2+L32MTjyfUhK49Ld2IlK9iZKlgKYi\n"
  "zyoatxdAjU8Xc5WPX692HO4/R9CGLsUfYcEEFU2R3EA=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_SIG3[] =
  "extra-info bob 3E1B2DC141F2B7C6A0F3C4ED9A14A9C35762E24B\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "K5GAkVjpUlofL78NIOE1VDxFn8yYbHK50rVuZG2HxqG/727bon+uMprv4MHjfDcP\n"
  "V3l9u1uUdGiUPOl8j+hRNw4z/ODeCj/24r2+L32MTjyfUhK49Ld2IlK9iZKlgKYi\n"
  "zyoatxdAjU8Xc5WPX692HO4/R9CGLsUfYcEEFU2=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_FP[] =
  "extra-info bob C34293303F0F1E42CB14E593717B834E8E53797D8888\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "IDA8ryUYeMx7+Au/xQmX7Y8fXksoHUOXmePND2JYM4rPfishQJ1LpQ15KrolOZDH\n"
  "FVIk3RmCefNlJeS1/UgWPcU8u2nGw1YQuRBHF4ViTmZ0OevI1pTsSApl4+oIx2dy\n"
  "DGgCQmKfMbaOixIK8Ioh1Z2NUfMkjbUUE2WWgFTAsac=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_FP_FP[] = "C34293303F0F1E42CB14E593717B834E8E53797D";
static const char EX_EI_BAD_FP_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAKXMSbif4fG+BW/5lIq5V1tMRondIUfKiNizp0E6EcBw5LvYfQV6zrj8\n"
  "HmMFbB/WGf9XGVMxIBzxzeQBRvCQJh+0QH7+ju5/isIHJZsACMILepr6ywmCcjVU\n"
  "iYRtC8zGQLqfkf2cNoo7AhcI5i/YzyW2u1zmbPX5J+8sUErfxydbAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_BAD_NICKNAME[] =
  "extra-info bobhasaverylongnameandidontthinkweshouldlethim A4EA2389A52459B3F7C7121A46012F098BDFC2A4\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "e2wLJFThRMGawxKrQPuH2XCLek/LJsg4XOB8waAjE0xdHOrzjur9x1jIxy7DVU6t\n"
  "z1edbIoL24qucMJvFy2xjSQhFRX4OsyNc0nWr3LfJnTW9aEmxuwXM+mltUD2uFN1\n"
  "2vYOIQjUmJwS2yfeSKnhXEl2PWVUmgzYL3r4S5kHco4=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_NICKNAME_FP[] = "A4EA2389A52459B3F7C7121A46012F098BDFC2A4";
static const char EX_EI_BAD_NICKNAME_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAKfq7oxD1kMu1+zeG2UVXN4vOu6FDp0V/olA3ttmXpUCgCiBxWTgtwNl\n"
  "nPf0HcKMaCp/0D9XrbhvIoOsg0OTf1TcJfGsA/zPG7jrWYa4xhD50KYvty9EINK9\n"
  "/UBWNSyXCFDMqnddb/LZ8+VgttmxfYkpeRzSSmDijN3RbOvYJhhBAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_BAD_TOKENS[] =
  "extra-info\n"
  "published 2014-10-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "e0b8fW9SkB81WwpkqR+/oLvVnNMpW4VwBKlNAnsPdInnNYySFCeILyOmb8A5j/D3\n"
  "ZRbfKFgXrApya4ViGeh+1QHz+FM8nWaK0+5JE6cNw+DNiQWsUjrvq2bHoZi/Lv+k\n"
  "RFkpbb0+IPdub9Jj3qn6cZBVSChD1aeCO9RkchV0744=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_TOKENS_FP[] = "1CE7F867C744F0CE635146D82C0A0CC4B3408E0A";
static const char EX_EI_BAD_TOKENS_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBALfrYfnIA7gTGwEC5tPqqTuSnMiINq/hPyMWXOFUEKEBRmctxba9fjiy\n"
  "JDstxC4ZBpdHc3+uuFn6krGgBVzFCKvBkBHUQXgFmjlANzdcLrG7J78K6gXuPeeq\n"
  "MbptD7thkuIdkPdVWMko7BrmBEr30EphgrKQqTWjrtBQj+CZ8Sr1AgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_BAD_START[] =
  "published 2014-10-05 20:07:00\n"
  "extra-info bob 5CCCACE71A9BDB5E8E0C942AB3407452350434C0\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "BOiWgexqCAMZ8uyJ7jwBwRkz7Ox8cT4BImkmkV3bQiZgcWvPiYA3EnCm2ye48Ldg\n"
  "zBST2p6zJM5o4MEDYGMxfViS86Abj/z7DOY1gtLhjmAaVjIIpXc3koxEZtzCecqy\n"
  "JQz6xEg9/KoEuoT0DRrfYQ+KtQfzBDWrotfOvEa1rvc=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_START_FP[] = "5CCCACE71A9BDB5E8E0C942AB3407452350434C0";
static const char EX_EI_BAD_START_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAK2OCIfM6Cin/lq99Z3w9tl6HeyGlkBZu9MQEPHxqGIHTq78lIC1UkrC\n"
  "6NTqlrHBV9dmfzdwJn4GgMWsCZafL0FPIH3HNyNKUxLgyjixyKljHx2rfErSfOxI\n"
  "bMoOGBKv7m1EZZ0O5uG9ly9MBiNGdJyLdlnVvH7wSCnYciizpO4lAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char EX_EI_BAD_PUBLISHED[] =
  "extra-info bob E67C477E3536BDE348BD407426D9679E5AE0BC16\n"
  "published 2014-99-05 20:07:00\n"
  "router-signature\n"
  "-----BEGIN SIGNATURE-----\n"
  "l45IziBaXRKIjPAIUogMFNjQgH6k6Vm0+6r5+oByr4sP+B3ufNdUA6+WqBs43F0Z\n"
  "IqcJiT9nFn0DuNd/liOyOCixppDLx5h5NrhoGqcT3ySADEEXhzjlmc35TI3YBNVO\n"
  "v98fotmwIEg9YRWVGPg6XuIn2PRyiboFyjUpaYGCV0Q=\n"
  "-----END SIGNATURE-----\n"
  ;

static const char EX_EI_BAD_PUBLISHED_FP[] = "E67C477E3536BDE348BD407426D9679E5AE0BC16";
static const char EX_EI_BAD_PUBLISHED_KEY[] =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAL7q8GEI18iv8Fo0QbNHmFatQ2FNacalPldpmKUdMJYEVZtdOR0nhcrY\n"
  "BvG6303md3INygg+KP49RvWEJR/cU4RZ9QfHpORxH2OocMyRedw2rLex2E7jNNSi\n"
  "52yd1sHFYI8ZQ4aff+ZHUjJUGKRyqpbc8okVbq/Rl7vug0dd12eHAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";
