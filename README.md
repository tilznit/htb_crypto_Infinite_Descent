# htb_crypto_Infinite_Descent
Writeup for the Infinite Descent crypto challenge on hackthebox 

Learn all about RSA [here](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). This challenge reveals a neat attack against RSA when adjacent primes are chosen for _n_. This enables us to ultimately decrypt the message (read: flag).

We are given three files:

```
fasterprimes.py     # home-grown code that "finds a specified length prime, then a neighbouring prime for speed."
AESbootstrap.py     # "This will be used as the pre-secret from the RSA exchange for bootstrapping the AES comms."
email.msg
```
The contents of the email:

```
Hi Rolly,

Just a quick update. We've addressed your issues with the numpy PSNG by ditching it and created a mersenne twister from scratch.
This will be used as the pre-secret from the RSA exchange for bootstrapping the AES comms.

We have some problems with the RSA generator that we're ironing out. Security have some questions around the
way primes are chosen but I think they're just getting in the way. To prove it's working just fine I've sent your
private key through secure comms and your public key is below with the message; we've also used this to encrypt a pre-shared
secret. Can you decrypt with your private key and check the pre-shared key works with the twister?

Have a good weekend,

CayceP


-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFbDk+zYy1tbjwPpsTWbYjIfBtZk
walARbJxLg6QhyalsGnBx064VFIH9XIKzPK/Dt1RzMO68gy7zLOiyipPtYb2n0M6
WcdDGgw9J9+xx4HjXZCHx4h4zQhfQeOYymeSPewXJOe+GT31ymz6/Q1Ulyq/jWnD
XZogxfbXi6bIwuN7AgMBAAE=
-----END PUBLIC KEY-----


-----BEGIN MESSAGE-----
41296290787170212566581926747559000694979534392034439796933335542554551981322424774631715454669002723657175134418412556653226439790475349107756702973735895193117931356004359775501074138668004417061809481535231402802835349794859992556874148430578703014721700812262863679987426564893631600671862958451813895661
-----END MESSAGE-----
```

In order to do interesting things with RSA, we need a bit more information. We have the ciphertext _c_ as

`412962907871702 ... 13895661`

We need Rolly's private key _d_ in order to decrypt. There are a couple of ways to get it depending on the strength of the [variables used to encrypt](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). Here's how I did it.

Let's extract info from the public key. I used [http://lapo.it/asn1js/](http://lapo.it/asn1js/) to get _e_ and _n_. You could also find the value of _e_ in the `fasterprimes.py` file.

```python
e = 65537
n = 60927735877056559130803069919621859729817223816091468870468728150535102345085544195001142179497747300756976118359991531766104121379004146329976732080428122272205922112100073487631152244297343150154109815442681320311122134731991282281969152492933055882377304091844616671159896354284349735375653609635116671867
```

in order to get _d_ we need to solve for `λ(n)=lcm(p-1)(q-1)`. We get _p_ and _q_ by entering _n_ into the app hosted at[https://www.alpertron.com.ar/ECM.HTM](https://www.alpertron.com.ar/ECM.HTM.

```python
p = 7805622068551395034983074294227914827932592556281432557101799867160043121996329164791493852142033952331091204125384233936237118904494182099698709037828123

q = 7805622068551395034983074294227914827932592556281432557101799867160043121996329164791493852142033952331091204125384233936237118904494182099698709037828129
```
notice that the difference _q_ and _p_ is only 6. This seems to be ... [bad](https://rjlipton.wordpress.com/2012/03/01/do-gaps-between-primes-affect-rsa-keys/).

We can calulate the least common multiple at [https://www.dcode.fr/lcm]https://www.dcode.fr/lcm(https://www.dcode.fr/lcm).

```python
λ(n) = 30463867938528279565401534959810929864908611908045734435234364075267551172542772097500571089748873650378488059179995765883052060689502073164988366040214053330480892504655001760741281894233843642484498626288783558355693907322873644811819784752614385907236320954718182951346011940023270373505727106108520507808
```
Because of math, _d_ is the modular multiplicative inverse of `e (mod λ(n))`. This was can be calculated at [https://www.boxentriq.com/code-breaking/modular-multiplicative-inverse](https://www.boxentriq.com/code-breaking/modular-multiplicative-inverse).

```python
d = 17313231079213639633992181075012861341660224897799280174172438841378384896661856501571726975735638616079423321974123354686362772974673760121811445161264821861652064058903828304325339662063166460289266152474968833094529430278281761061095864975447082068158811210147450176325336233243919134711602786122617068737
```
As a side note: [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking) and [https://www.dcode.fr/](https://www.dcode.fr/) are great online resources for solving crypto challenge math problems.

We now have the private key _d_.

