#!/usr/bin/python2

'''
# Cipher Suite ECDHE-RSA-AES256-GCM-SHA384
CLIENT_RANDOM 52362c10a2665e323a2adb4b9da0c10d4a8823719272f8b4c97af24f92784812 9F9A0F19A02BDDBE1A05926597D622CCA06D2AF416A28AD9C03163B87FF1B0C67824BBDB595B32D8027DB566EC04FB25
CLIENT_RANDOM 52362c1012cf23628256e745e903cea696e9f62a60ba0ae8311d70dea5e41949 9F9A0F19A02BDDBE1A05926597D622CCA06D2AF416A28AD9C03163B87FF1B0C67824BBDB595B32D8027DB566EC04FB25

alea1 = 52362c10a2665e323a2adb4b9da0c10d4a8823719272f8b4c97af24f92784812
alea2 = 52362c1012cf23628256e745e903cea696e9f62a60ba0ae8311d70dea5e41949

sk = 9F9A0F19A02BDDBE1A05926597D622CCA06D2AF416A28AD9C03163B87FF1B0C67824BBDB595B32D8027DB566EC04FB25

curve : secp256r1 (0x0017)

cryptography.hazmat.primitives.asymmetric.ec.derive_private_key(private_value, curve, backend)
    => construit une priv key avec l'alea 1 et l'alea 2
    => construire les clés publique grâce aux clé privé
    => fonction pour calculer sk

# Cipher Suite ECDH-RSA-AES256-GCM-SHA384
CLIENT_RANDOM 52362c10f92c6848635641f3c49ed0c9dc3351657ad53e66584a143754c4c209 1427AC9167559BDEAB30EBB300D6C8E17CB53D504356192EFF47CBAF8B5D3B7F45EF470D67FC15E9B57C38A834B8CC7B
CLIENT_RANDOM 52362c10ba0c1f836bc378c65f21bb4ab9316fbabfbaa20aacf76a61c3ab2b88 1427AC9167559BDEAB30EBB300D6C8E17CB53D504356192EFF47CBAF8B5D3B7F45EF470D67FC15E9B57C38A834B8CC7B
'''

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib

srv_rand = 0x14dc64b05d6b5e733e6d55f257b88fa3abfdbefb5cf7def9fa9c825c
cli_rand = 0xf5dfcad5d6b57d522e835df254ab8b6a63b10b45b4a62a8b82f0ac45

srv_priv_key = ec.derive_private_key(srv_rand, ec.SECP256R1(), default_backend())
cli_priv_key = ec.derive_private_key(cli_rand, ec.SECP256R1(), default_backend())

srv_pub_key = srv_priv_key.public_key()
cli_pub_key = cli_priv_key.public_key()

shared_key = srv_priv_key.exchange(ec.ECDH(),srv_pub_key)

print(hashlib.sha256(shared_key).hexdigest())