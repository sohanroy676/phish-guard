# Email data audit

## Messages per source

| source | seen | kept | unparseable | too large | too short | exact duplicates |
|---|---|---|---|---|---|---|
| enron | 6000 | 5443 | 0 | 0 | 20 | 105 |
| nazario | 3466 | 2792 | 4 | 7 | 10 | 393 |
| spamassassin | 4150 | 3968 | 0 | 0 | 0 | 58 |

## Kept phishing per Nazario year

- 2015: 257
- 2016: 418
- 2017: 271
- 2018: 235
- 2019: 190
- 2020: 126
- 2021: 86
- 2022: 166
- 2023: 338
- 2024: 304
- 2025: 401

## Single-feature ROC-AUC

| feature | phishing vs ham | Enron vs SpamAssassin |
|---|---|---|
| n_links | 0.739 | 0.128 |
| n_link_domains | 0.679 | 0.118 |
| ip_link_ratio | 0.500 | 0.502 |
| shortener_links | 0.527 | 0.499 |
| anchor_mismatch_count | 0.534 | 0.499 |
| script_links | 0.500 | 0.500 |
| has_html | 0.964 | 0.479 |
| n_attachments | 0.588 | 0.485 |
| log_text_len | 0.380 | 0.433 |
| subject_len | 0.629 | 0.336 |
| exclaim_count | 0.461 | 0.433 |
| upper_ratio | 0.504 | 0.723 |
| money_tokens | 0.469 | 0.529 |
| urgency_words | 0.850 | 0.546 |

## Flags

Features that separate the two ham corpora (source artefacts; add to `exclude_features` or move to rules): n_links, n_link_domains
Features with a near-perfect phishing vs ham AUC (> 0.95): has_html

## Most source-specific tokens

Tokens like corpus names, list footers or dates belong in `artefact_stoplist.txt`.

### enron

thanks (32%), call (22%), let (22%), me (38%), attached (19%), meeting (11%), questions (17%), fax (12%), forward (12%), agreement (10%), will (47%), any (35%), know (28%), trading (8%), following (13%), na (8%), north (8%), deal (10%), may (24%), week (13%)

### nazario

account (54%), your (88%), dear (40%), click (34%), email (50%), security (26%), below (31%), update (25%), verify (15%), notification (15%), customer (18%), mailbox (14%), mail (30%), reply (16%), service (19%), kindly (12%), message (28%), reserved (17%), view (15%), team (18%)

### spamassassin

it (72%), but (50%), just (35%), that (70%), so (38%), my (37%), emailtoken (65%), un (15%), one (34%), don (26%), there (36%), ve (21%), more (30%), they (32%), what (33%), can (44%), then (22%), group (24%), was (35%), use (27%)

## Source files

- `_archives/20030228_easy_ham.tar.bz2`: `2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438`
- `_archives/20030228_easy_ham_2.tar.bz2`: `b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38`
- `_archives/20030228_hard_ham.tar.bz2`: `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9`
- `_archives/enron_mail_20150507.tar.gz`: `b3da1b3fe0369ec3140bb4fbce94702c33b7da810ec15d718b3fadf5cd748ca7`
- `nazario/phishing-2015.mbox`: `7523e62a5e6e4ee8134ab8b1a628e423097a7779e1003b28422864aa34f1c319`
- `nazario/phishing-2016.mbox`: `42393e4d686193bfb879d1608c23fd4d3b698ccd4d73f0e1d2276ba709718483`
- `nazario/phishing-2017.mbox`: `110fba876b38b44035bf065788952674bc68a7b6879c345a515a9ac844b1d704`
- `nazario/phishing-2018.mbox`: `83f49cf2a76c7b29b205d22d8778e46848e36af0f15ee1df126a543696acd48d`
- `nazario/phishing-2019.mbox`: `cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e`
- `nazario/phishing-2020.mbox`: `99e20bf25f5e8556d37103f2c8140cd75181a62d3df91df8acf9d9aece9f08bb`
- `nazario/phishing-2021.mbox`: `636707cff42245d1482e4ae8a2c03369717a5e06bf9d1a0f4ec5dcd846661cee`
- `nazario/phishing-2022.mbox`: `a6291e2cb990204766fce425423949b403cce4ae6a660fc8d08812e40a063fa7`
- `nazario/phishing-2023.mbox`: `5007f1c1dc91b15e93e988afa3a1cf402e15c88f765d3057be8bfec50dae1fe8`
- `nazario/phishing-2024.mbox`: `60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99`
- `nazario/phishing-2025.mbox`: `f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f`
