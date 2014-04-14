Uitdaging! (cryptografie)
Deze opgave is een uitdaging! Deelnemen is niet verplicht, en een
pasklaar antwoord is er niet.
Wie een of meer van de deelopgaven wel tot een goed einde brengt, voor
20 april 2014, kan een bescheiden bonus op zijn/haar cijfer voor dit
vak tegemoet zien: in principe tot maximaal 0,5 punt op het eindcijfer,
maar ter beoordeling aan mij o.b.v. aanpak, groepsgrootte, gebleken
moeilijkheidsgraad, etc.

Aangezien de WES-cipher uit de vorige huiswerkopgave niet sterk genoeg
gebleken is, beschouwen we nu een variant die ik 3WES+ noem: het is
Triple-WES met aan het begin een zgn. "key whitening" stap.
Om precies te zijn: elk te versleutelen byte wordt eerst geEXORd met
8 sleutelbits, en dan drie keer WES-geëncrypt met telkens 24 sleutelbits.
In totaal is de sleutel dus 80 bits lang.

Om je implementatie van 3WES te controleren, geef ik het volgende
testgeval: als de sleutelbytes achtereenvolgens 01 03 07 0f 1f 3f 7f fe fc f8
hexadecimaal zijn, en de plaintext 41 hexadecimaal, dan is de ciphertext
a0 hexadecimaal.

Hieronder staan vier deelopgaven, in moeilijkheidsgraad oplopend doordat
meer sleutelbits gevonden moeten worden. In elk van deze gevallen zijn
een aantal plaintext/ciphertext paren gegeven, en is er een te decrypten
ciphertext.
Inleveren gaat dit keer niet via blackboard, maar via e-mail aan de
docent (p.t.deboer@utwente.nl).

----------------------------------------------
Brons (laatste 4 sleutelbytes zijn gelijk):

Onderschepte plaintext/ciphertext paren (hex):
  0x41, 0xfd,
  0x42, 0x2f,
  0x43, 0x1a,
  0x44, 0xcd,
  0x45, 0x06,
  0x46, 0x8b,
  0x47, 0x1b,
  0x48, 0xbc,
  0x49, 0x1e,
  0x4a, 0x53,
  0x4b, 0x50,
  0x4c, 0xd4,

Te decrypten ciphertext (ASCII, ECB-mode):
0f f6 a3 62 a5 b5 0f ca 0f 92 27 ca 13 62 14 bb
b5 c0 bf 81 ca 89 20 89 a4 89 89 c7 89 4b

# antwoord
key := [10]uint8{ 0, 90, 238, 27, 202, 178, 135, 135, 135, 135 }
plaintext := {97, 108, 103, 101, 98, 114, 97, 32, 97, 110, 100, 32, 115, 101, 99, 117, 114, 105, 116, 121, 32, 49, 57, 49, 53, 49, 49, 52, 49, 48}
"algebra and security 191511410"

----------------------------------------------
Zilver (laatste 3 sleutelbytes zijn gelijk):

Onderschepte plaintext/ciphertext paren (hex):
  41 51
  42 c4
  43 8e
  44 cb
  45 d0
  46 a0
  47 e8
  48 88
  49 e4
  4a 9e
  4b f5
  4c 3b

Te decrypten ciphertext (ASCII, ECB-mode):
d0 ae 4f 7c cf ea a6 2d d8 e8 4f 50 7d cf ea d8
42 8d 42 42 d8 42 8d 24 f3 d8 f3 5c cc 7d

----------------------------------------------
Goud (laatste 2 sleutelbytes zijn gelijk):

Onderschepte plaintext/ciphertext paren (hex):
  41 43
  42 10
  43 f7
  44 76
  45 d6
  46 6c
  47 0c
  48 29
  49 97
  4a 37
  4b e7
  4c 98

Te decrypten ciphertext (ASCII, ECB-mode):
d6 6c 19 3a 5d d6 6c 19 f3 5d d6 6c 19 f3 43 5d
3a 37 7b 5d 3a 1d 3a 5d 3a e7 77 5d 77 f0 f3 5d
0c 9d 4d f7

----------------------------------------------
Platina:

Onderschepte plaintext/ciphertext paren (hex):
  41 13
  42 2c
  43 f1
  44 a4
  45 dc
  46 fa
  47 db
  48 6d
  49 49
  4a 9a
  4b 58
  4c 91

Te decrypten ciphertext (ASCII, ECB-mode):
fc 4e d9 53 39 d9 13 a2 4e 92 a2 f4 92 d9 2a 5d
d9 e2 0c 0c 92 84 d9 b8 53 26 8a