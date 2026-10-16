# URL data audit

Source: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`  
SHA-256: `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`

## Warnings
- The https rate differs by 51% between classes. `is_https` would act as a shortcut feature: set `exclude_features: [is_https]` in configs/url.yaml and let the scheme be handled by rules instead.

## Class counts (y = 1 is phishing; PhiUSIIL label 1 is legitimate)
| | rows |
|---|---|
| Total | 235795 |
| Phishing (label 0) | 100945 |
| Legitimate (label 1) | 134850 |

## Cleaning
- Exact duplicate URLs: 425
- Unsupported (not http/https or unreadable): 8
- Duplicates after normalisation (scheme + host/path/query): 645
- Host/path/query strings labelled both ways: 42
- Distinct registered domains: 175507

## Per class (normalisable URLs)
| | rows | https rate | empty-path rate | domains |
|---|---|---|---|---|
| Phishing | 100937 | 48.7% | 72.8% | 43510 |
| Legitimate | 134850 | 100.0% | 100.0% | 132117 |

https-rate gap: 51.3%
