# Email model false positives on modern legitimate mail: research report

Researched 2026-10-16 with web search. Every claim cites its source. Where I am inferring rather than quoting a source, the text says **(inference)**.

## 1. Recommendation (what to do, in order)

**The main finding:** I could not find any public corpus of real, English, modern (2015 or later) commercial or transactional legitimate email that has a licence you can cite. The two real corpora that exist (PrivacyMail's 500,000 newsletters and Princeton's political email corpus) are request-only and carry no licence ([Zenodo 6509751](https://zenodo.org/records/6509751), [electionemails2020.org](https://electionemails2020.org)). Every freely licensed "modern ham" set I checked is synthetic, LLM-rephrased, or of unknown origin (section 2). Retraining therefore can't be step 1 within 2 to 3 weeks. The fix that fits your constraints is to stop the text model speaking outside the domain it was trained on, and to use the bulk-mail evidence that modern headers already carry.

Do these in order:

1. **Freeze the evaluation first (half a day).** Lock the 123 Gmail messages as "Test A" and write down the protocol in section 6 before changing anything. Every rule, list and threshold below is decided from training data, public lists and RFCs only, never from Test A. Then measure on the Nazario training data (all years) how often phishing carries the signals used below: `List-Unsubscribe`, an aligned `dmarc=pass` in the topmost Authentication-Results header, and links through tracking or redirector domains. That number is your recall cost, and measuring it is allowed because Nazario is training data.
2. **Add offline bulk-mail rules (1 to 2 days).** Since February 2024, Gmail requires bulk senders (more than 5,000 messages a day) to pass SPF, DKIM and DMARC with From-domain alignment, and requires marketing mail to carry `List-Unsubscribe` with an HTTPS URL plus `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 2369 and RFC 8058) ([Google sender guidelines](https://support.google.com/mail/answer/81126?hl=en)). So almost all of your 123 messages should carry headers that 1999–2003 ham never had and that most phishing lacks. These are rules in the existing rules layer, not model features. As model features they would fail your own artefact check, because Enron has no such headers and the model would learn the source.
   - `bulk_mail` (info): any of `List-Unsubscribe`, `List-Id`, `Precedence: bulk|list`, or a mailing-list marker. The header set comes from the rspamd `maillist` module ([rspamd docs](https://docs.rspamd.com/modules/maillist), Apache-2.0).
   - `bulk_sender_authenticated` (info): `bulk_mail` holds and the topmost Authentication-Results shows `dmarc=pass` with `header.from` aligned. Use your existing `auth_verdicts()` helper.
3. **Change the band policy to a domain-of-competence gate (1 day).** This refines your "Can't assess" idea. Apply it only where the model is out of domain, so its recall on non-bulk phishing is left alone:
   - If `bulk_mail` holds and no strong rule fires (`auth_fail`, `display_name_brand_spoof`, `anchor_href_mismatch`, `link_flagged` after step 4), the text model alone can't give High or Suspicious. The band becomes **Can't assess**, with the fixed wording "This looks like bulk or marketing mail, which the text model was not trained on." The top n-grams are still shown as model reasons.
   - Low still needs positive evidence: `bulk_sender_authenticated`, text Low, and every link Low or discounted. Authentication must never produce Low on its own, because replayed PayPal and Apple invoices pass DKIM and DMARC ([Kaseya](https://www.kaseya.com/blog/dkim-replay-attacks-apple-paypal-invoice-abuse/)), and phishers send through SendGrid ([BleepingComputer](https://www.bleepingcomputer.com/news/security/hmrc-phishing-scam-abuses-mail-service-to-bypass-detection), [Kaseya](https://www.kaseya.com/blog/how-threat-actors-use-sendgrid-and-callback-phishing-for-openai-scam/)).
   - In Mode A (fields only, no headers), a text-only firing is capped at Suspicious, with "header checks unavailable" shown.
4. **Discount tracking and redirector links (1 day).** Build the list from licensed sources (section 4): rspamd `redirectors.inc` (about 1,200 shortener and link-wrapping domains, Apache-2.0) plus the email-tracking domains in EasyPrivacy (GPLv3 or CC BY-SA 3.0). A link whose registered domain is on the list gets "Can't assess (tracking redirect)" and is left out of the worst-link maximum. When the anchor text is itself a URL, score the anchor's domain instead. For short famous domains, use the Majestic Million (CC BY 3.0) as a context signal. Exclude user-content hosts (sites.google.com, forms, sharepoint, firebaseapp and similar) from any dampening, and check the share of PhiUSIIL phishing on top-N domains before you adopt it.
5. **Re-run Test A once, and report before-and-after numbers with recall on the newest Nazario year.** (Inference) Expect most of the 123 to move from High to Can't assess, some to Low, and some to stay Suspicious through rules. Report whatever actually happens.
6. **If time remains, start collecting modern ham for v1.1 retraining** (section 5, approach A). Collecting is slow (newsletters arrive at their own pace), so start the seed mailbox on day 1 even if retraining waits.
7. **Leave per-category thresholds until you have labelled modern ham.** Recalibrating on 1999–2003 dev data can't fix this (section 5, approach E).

## 2. Datasets

"Usable" means real, modern, English legitimate mail with a licence you can cite. No dataset in this table meets all four.

| Name | URL | Licence | Size | Real or synthetic | Raw or features | Usable? |
|---|---|---|---|---|---|---|
| PrivacyMail commercial newsletters (Maass, Schwär, Hollick, TU Darmstadt, 2022) | https://zenodo.org/records/6509751 | **None.** The authors state that no licence is applied. Request-only with a research purpose, and raw data may not be shared | ~500,000 newsletters, 1.0 TB | Real, crowdsourced newsletters received at registered identities. Likely over-represents German | Raw `.eml`, organised by website | **No (licence unclear).** The closest thing to what you need. You could request it and ask for written terms |
| Princeton Corpus of Political Emails (Mathur et al., 2020 US election) | https://electionemails2020.org · https://citp.princeton.edu/news/2020/citp-researchers-release-princeton-corpus-political-emails-website | **Not stated.** Google Form request | ~250k (CITP news) to ~948k emails (site, Sep 2021) | Real bulk political mail | Not stated | **No (terms unclear, narrow genre)** |
| Englehardt et al. email-tracking corpus (PoPETs 2018) | https://www.petsymposium.org/popets/2018/popets-2018-0006.pdf | Emails not released. Only a list of leaking URLs, with no licence stated | 12,618 HTML emails from 902 senders, 2017 | Real newsletters | Not available | **No** |
| TREC 2007 Public Spam Corpus | https://plg.uwaterloo.ca/~gvcormac/treccorpus07/about.html | Research-use Usage Agreement, no redistribution (citable) | 25,220 ham, 50,199 spam, Apr–Jul 2007 | Real | Raw messages | Licensed but **not modern** |
| Avocado Research Email Collection (LDC2015T03) | https://catalog.ldc.upenn.edu/LDC2015T03 (listed in https://github.com/Mithileysh/Email-Datasets) | LDC licence. **Not verified** (page not opened) | Not verified | Real corporate mail, an older era (unverified) | Not verified | **No** (not commercial mail, not modern) |
| Phishing Email Curated Datasets (Champa et al.) | https://zenodo.org/records/8339691 | CC BY 4.0 | 11 CSVs, 449 MB | Real, but re-packaged Enron, SpamAssassin, TREC 05–07, CEAS-08, Ling, Nazario, Nigerian. Range given as 1995–2022 | CSV | Licensed, but **no modern ham** |
| DataPhish PhishingSpamDataSet (arXiv 2511.21448) | https://arxiv.org/html/2511.21448v2 · https://github.com/DataPhish/PhishingSpamDataSet | **Not stated in the paper.** The repo page failed to load | ~3,000 legitimate from personal and work accounts, plus ~9,000–12,000 LLM rephrasings | **Mixed:** human-written originals plus LLM-rephrased copies, with a "Created by" field | Not verified | **No (licence unclear)**. If it turns out to be licensed, keep only the human-written rows |
| Multi-Source Phishing, Spam, Ham dataset (IEEE DataPort, May 2026) | https://ieee-dataport.org/documents/multi-source-phishing-spam-ham-email-dataset-spf-url-and-structural-features | **Not stated.** Subscription required | ~546 MB CSV | Re-packaged (Nazario, MeAJOR, phishing_pot, realprogrammersusevim). The ham source isn't stated | **Features only** (SPF, URL, structural) | **No** |
| realprogrammersusevim/email-dataset | https://github.com/realprogrammersusevim/email-dataset | A LICENSE file exists but the type wasn't shown. **Unverified** | 10,776 ham, 8,752 spam | **Unknown provenance and years** | ASCII-cleaned text files | **No** |
| marketeam/Marketing-Emails (Hugging Face) | https://huggingface.co/datasets/marketeam/Marketing-Emails | MIT | 16,440 | **Synthetic** ("fully synthetic", generated from more than 10,000 personas) | CSV text | Licensed but synthetic. Don't use it as ham |
| jason23322/high-accuracy-email-classifier (Hugging Face) | https://huggingface.co/datasets/jason23322/high-accuracy-email-classifier | Apache-2.0 | ~12,000 (Promotions, Updates, Verify Code, Forum, Social, Spam) | **Unknown.** "Based on common email patterns and templates", so treat it as synthetic | Text | **No** (provenance unknown) |
| darkknight25/phishing_benign_email_dataset | https://huggingface.co/datasets/darkknight25/phishing_benign_email_dataset | MIT | 200 rows | Looks illustrative or hand-written | Text | **No** |
| Postmark transactional templates (ActiveCampaign) | https://github.com/ActiveCampaign/postmark-templates | MIT | 10 templates × 3 layouts (welcome, password reset, receipt, invoice, dunning, trial expiring, and others) | **Real-world templates, not real mail** | HTML/text templates | Only as a small, labelled augmentation probe, never as the ham class |
| Spanish phishing and legitimate dataset (Data in Brief, 2026) | https://www.sciencedirect.com/science/article/pii/S2352340926004427 | **Not verified** (page blocked to fetch) | Not verified | Not verified | Not verified | **No** (Spanish, so out of scope) |
| **Modern phishing (for testing recall):** phishing_pot | https://github.com/rf-peixoto/phishing_pot | CC BY-NC 4.0 (LICENSE file checked) | Not stated. Repo since Sep 2022, "last public commit" | Real honeypot phishing | Raw `.eml` | Usable for a non-commercial project as a modern phishing test set |
| EPVME malicious email dataset | https://github.com/sunknighteric/EPVME-Dataset/ | GPL-3.0 | 37,283–49,136 EML (README is inconsistent) | Crafted attack samples (header injection, spoofing, MIME tricks), not organic mail | Raw `.eml` | Malicious only. Useful for testing header rules, not the text model |
| **Self-collected seed mailbox** (approach A below) | n/a | You own the collection. Senders keep copyright in content, so use it locally for research and don't redistribute it. Not legal advice | (Inference) ~1,500–4,000 messages in 2 to 3 weeks from 200–400 subscriptions | Real | Raw `.eml`/mbox | Yes, cited as "author-collected, not released" |

Ruled out as you asked: MeAJOR ([arXiv 2507.17978](https://arxiv.org/abs/2507.17978)) and synthetic Kaggle sets.

## 3. Papers (one line on why each matters)

**Era and source shift, training only on old ham**
- Pendlebury et al., *TESSERACT*, USENIX Security 2019. Training data must precede test data, and benign and malicious samples must come from overlapping time windows. Your setup (ham 1999–2003, phishing 2015–2025) breaks that second rule. https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury · https://ar5iv.labs.arxiv.org/html/1807.07838
- Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022. Names sampling bias (P1), spurious correlations (P4) and lab-only evaluation (P9), and recommends not mixing incompatible sources and using explanations to find shortcut features. https://arxiv.org/pdf/2010.09470
- *Cross-Dataset Fragility of Phishing Detectors*, NHSJS 2026. Enron and Nazario training is almost the same setup as yours. At a fixed 5% FPR threshold, FPR rose from 0.049 to 0.811 on unseen human ham, and the ranking itself collapsed (ROC-AUC 0.529), so no threshold could fix it. Adding a source to training fixed only that source. Caveat: a student journal. https://nhsjs.com/2026/cross-dataset-fragility-of-phishing-detectors/
- Chakravorty et al., *Context-Aware Phishing Email Detection Using ML and NLP*, arXiv 2603.27326 (2026). LR on TF-IDF, like your `lr_text`. Its authors note that Enron tokens act as legitimate indicators, and their model flagged a promotional email as phishing at 90%. https://arxiv.org/html/2603.27326v1
- Jáñez-Martino et al., *A review of spam email detection: spammer strategies and the dataset shift problem*, AI Review 2022. Filters trained on old corpora showed error rates far above their in-corpus estimates on newer mail (Ling-Spam up to 48.8%), and the review discusses drift types and mitigations. https://link.springer.com/article/10.1007/s10462-022-10195-4
- Fernando and Komninos, *Evaluating and Combatting the Impact of Concept Drift on ML-Based Phishing Detection*, arXiv 2606.11471 (2026). Phishing URL detectors decay across 2016–2024, and some FPRs stay high even after mitigation. Relevant to your URL side. https://arxiv.org/pdf/2606.11471

**Legitimate mail is mostly machine-generated (why prose-only ham is the wrong negative class)**
- Grbovic et al., *How Many Folders Do You Really Need?*, CIKM 2014 (Yahoo). Machine-generated non-spam is about 90% of Yahoo mail. https://www.arxiv.org/pdf/1606.09296
- Kang, Shang and Langlois, *Classifying Emails into Human vs Machine Category*, AAAI 2022 (Yahoo). Human mail is only 3–5% of all messages. https://arxiv.org/pdf/2112.07742
- Yih, McCann and Kolcz, *Improving Spam Filtering by Detecting Gray Mail*, CEAS 2007. Bulk mail that users disagree about is its own category, and a separate gray-mail detector improves the main filter. This supports handling bulk mail separately rather than forcing it into the binary. https://www.microsoft.com/en-us/research/publication/improving-spam-filtering-by-detecting-gray-mail/

**Calibration and thresholds under shift**
- Ovadia et al., *Can You Trust Your Model's Uncertainty?*, NeurIPS 2019. Calibration fitted on in-distribution data degrades under dataset shift, so re-fitting thresholds on old dev data won't transfer. https://papers.nips.cc/paper/2019/hash/8558cb408c1d76621371888657d2eb1d-Abstract.html
- Saerens, Latinne and Decaestecker, *Adjusting the Outputs of a Classifier to New a Priori Probabilities*, Neural Computation 2002. Fixes label-proportion shift only. Your problem is covariate shift, so this does not apply. Cite it to explain why you didn't use it. https://mlanthology.org/neco/2002/saerens2002neco-adjusting
- Ding et al., *Class-Conditional Conformal Prediction with Many Classes*, NeurIPS 2023. Per-group (Mondrian) thresholds with guarantees need calibration data from each group, which you don't have for modern categories yet. https://arxiv.org/pdf/2306.09335
- Berjawi, Fahs and Khatoun, *AURA: Adaptive Uncertainty-Routed Analysis for Email Threat Detection*, arXiv 2609.19873 (Sep 2026). Routes only uncertain messages onward. It uses a transformer, which is out of scope for you, but the routing-on-uncertainty idea supports a Can't-assess band. I couldn't read the PDF, so its training corpora are **unverified**. https://arxiv.org/abs/2609.19873

**Bulk-mail and newsletter measurement (background for the header rules)**
- Englehardt et al., *I never signed up for this!*, PoPETs 2018. Newsletters are full of tracking links, which explains why your link bands fire on legitimate mail. https://www.petsymposium.org/popets/2018/popets-2018-0006.pdf
- Maass et al., PrivacyMail (TU Darmstadt). https://tuprints.ulb.tu-darmstadt.de/8725

## 4. Repos, rule sources and lists

| Source | Licence | Why it matters |
|---|---|---|
| rspamd `conf/maps.d/redirectors.inc` https://github.com/rspamd/rspamd/blob/master/conf/maps.d/redirectors.inc | Apache-2.0 ([repo](https://github.com/rspamd/rspamd)) | About 1,200 shortener and link-wrapping domains (bit.ly, t.co, safelinks.protection.outlook.com, mimecast, proofpoint). The cleanest licensed seed for link discounting |
| rspamd `maillist` module https://docs.rspamd.com/modules/maillist | Apache-2.0 | The exact header set production filters use to recognise list and bulk mail (List-*, Precedence, X-Loop, Mailman, Google Groups) |
| rspamd/maps https://github.com/rspamd/maps/ | Apache-2.0 | Shipped maps, including freemail lists. Directory contents weren't listed, so check them yourself |
| Apache SpamAssassin `60_welcomelist_dkim.cf` https://github.com/apache/spamassassin/blob/trunk/rules/60_welcomelist_dkim.cf | Apache-2.0 | About 60 DKIM-verified legitimate senders. Small and old. It also teaches a warning: the `USER_IN_DEF_DKIM_WL` bonus has let phishing through ([cPanel thread](https://support.cpanel.net/hc/en-us/community/posts/38497217740567-Spamassassin-new-rule-7-5-USER-IN-DEF-DKIM-WL-From-address-is-in-the-default-DKIM-welcome-list?page=1)), so discount, never allow-list |
| EasyPrivacy https://easylist.to/pages/licence.html | GPLv3+ or CC BY-SA 3.0+ (your choice) | Tracker domains, many of them email click and open trackers. Filter to entries matching your links |
| DuckDuckGo Tracker Radar https://github.com/mainzelM/tracker-radar/blob/main/README.md | CC BY-NC-SA 4.0 | Rich tracker metadata. Non-commercial only |
| Majestic Million https://majestic.com/reports/majestic-million?s=500 | CC BY 3.0 | A clearly licensed popularity list for the "short famous domain" problem |
| Tranco https://tranco-list.eu/ | **No licence stated.** It mixes sources, including Cloudflare Radar (CC BY-NC 4.0) | A better research list, but the licence is unclear. Prefer Majestic |
| Ugly Email tracker list https://github.com/OneClickLab/ugly-email-trackers | **Not stated** (the extension itself is MIT, https://uglyemail.com/) | Regexes for email tracking pixels. Don't use until the licence is confirmed |
| pihole email-tracker blacklist https://tomevault.io/tome/jaybocc2/pihole-email-tracker-blacklist | **Not stated** | Same, not usable |
| Englehardt leaking-URL list https://gist.github.com/englehardt/6438c5d775ffd535b317d5c6ce3cde61 | **Not stated** | Same, not usable |
| kregg34/EmailHeaderAnomalyDetection https://github.com/kregg34/EmailHeaderAnomalyDetection | **Not stated** | 94 header features, TREC07 ham plus Nazario. Shows header features separate classes in old corpora. Its ham is 2007 |
| Header-analysis rule tools: https://github.com/KaanTuran28/Phishing-Email-Header-Analyzer, https://github.com/fmohammed1-matc/phishlens | Not checked | Rule-based SPF, DKIM, DMARC, Reply-To and display-name checks, like your rules layer. Several similar repos call VirusTotal, which you can't use offline |
| Google email sender guidelines https://support.google.com/mail/answer/81126?hl=en | n/a (policy) | The primary source for why modern legitimate bulk mail carries aligned DMARC and one-click List-Unsubscribe |

I didn't find any open-source phishing email detector that trains on licensed modern ham, or that publishes a List-Unsubscribe-based bulk-versus-phishing feature with an evaluation. Production filters (rspamd, SpamAssassin) handle it with rules, which matches what I recommend.

## 5. Approaches compared

| | Approach | Fits constraints? | What it fixes | Cost | Risk |
|---|---|---|---|---|---|
| A | **Retrain with modern ham** | Yes, if the data is self-collected (no public licensed source exists) | The root cause: era and style | Collecting takes 2+ weeks, then retraining and the artefact loop | Data from one person or a few senders, so the model may learn senders. The licence is "own collection", not public |
| B | **Band policy: Can't assess when the text model fires out of domain** | Yes | The worst user harm (false High) right away. Explainable | ~1 day | Some phishing that carries List-Unsubscribe and no strong rule gets Can't assess instead of High. Measure this on Nazario |
| C | **Discount tracking and mail-service link domains** | Yes, using the Apache-2.0 and GPL/CC BY-SA lists above | The link half of the final band (96 of 123 links were Suspicious or High) | ~1 day | Phishing through real redirectors (open redirects, SendGrid click domains) loses its link signal. Never mark such a link Low |
| D | **Offline bulk-mail rules from headers** | Yes, headers only with no lookups, using the topmost Authentication-Results you already trust | Gives B its trigger and gives Low positive evidence | ~1 day | Phishers can add List-Unsubscribe, and DKIM-replay or ESP-abuse phishing passes authentication. That's why D can only gate the text model and never prove safety |
| E | **New thresholding (calibration, per-category thresholds)** | Not now | Little without modern labels: calibration on old dev doesn't transfer (Ovadia), and per-category thresholds need per-category calibration data (Ding) | Low code, but no data | Tuning on Test A would leak it. The NHSJS study found the ranking itself failed on unseen ham, so thresholds can't rescue it |
| F | **Out-of-distribution score** (anything else) | Yes | Generalises B beyond headers: for example, the share of the message's TF-IDF mass in vocabulary seen in training ham, or the distance to the nearest training ham. High distance gives Can't assess | 1 to 2 days | A threshold choice on training-only data. Treat it as optional after B |

**Recommendation:** do D, then B, then C now, plus F if time allows. Start A's collection on day 1 for v1.1. Leave E until A exists.

**Approach A details (inference, since no paper gives a ham-size rule for this setup):**
- Source: create a new mailbox and subscribe it to 200–400 English senders across categories (retail, banks and payments, travel, SaaS notifications, newsletters, social). Sign up for accounts so receipts and security notifications arrive. Export as mbox. Optionally, use your own older Gmail mail, but only from senders and dates disjoint from Test A.
- Mix: aim for at least as many modern ham messages as Nazario phishing in its last 3–5 years, drawn from at least 300 distinct sender registered domains. Keep Enron and SpamAssassin as a minority (under 50%) so era stops being the main separator. NHSJS found that adding a source only fixed that source, so sender diversity matters more than raw count.
- Mask sender brand names and domain tokens as well as URLs, and split by sender registered domain (GroupKFold), so the model can't memorise senders.
- Re-run your artefact loop: expect tokens like "unsubscribe", "view in browser" and "©" to show up as ham markers, which is legitimate style but easy for phishers to copy. Report it.

## 6. Evaluating false positives honestly with one mailbox

One mailbox can show that a problem exists (your 123 do: 101 of 123 High, Wilson 95% CI 74–88%), but it can't support a general FPR claim after a fix. Messages from one person cluster by sender, and every design choice risks quietly fitting that mailbox.

Method:
1. **Pre-register.** Freeze the model, thresholds, rules and lists, and write down the metrics, before opening any test set. Run each test set once and report every run.
2. **Keep Test A (your 123) untouched**, and report it separately as "single mailbox, development-era evidence."
3. **Build Test B: about 400 legitimate messages from at least 5 mailboxes** (consenting friends or family). Score them locally and keep only band, category, sender registered domain and HMAC, which matches your storage rule. Stratify by category (newsletter, receipt or payment, account or security notification, promotion, personal) with 60 or more per category. Make them sender-disjoint from any training ham, and received after the training cutoff.
4. **Statistics.** Report FPR (High or Suspicious) and the High-only rate per category with Wilson 95% intervals. Bootstrap over senders, not messages, because messages from one sender are correlated. The effective sample size is closer to the number of distinct senders, so aim for 150 or more sender domains.
   - Sizes: with 0 false positives in n messages, the 95% upper bound is about 3/n ([rule of three](https://en.wikipedia.org/wiki/Rule_of_three_(statistics))). So 60 per category supports "FPR ≤ 5%" per category, and 300 overall supports "≤ 1%". To estimate an FPR near 10% to within ±3 points you need about 385 messages, and near 5% to within ±2.5 points about 292.
5. **Report the recall cost beside it**: TPR on the newest Nazario year (your temporal test) and on phishing_pot (CC BY-NC 4.0), both with and without the policy change. Also report the share of each that lands in Can't assess, because a Can't assess band that swallows phishing is a cost too.
6. **Report the Can't assess rate on Test B** as its own number. Moving false Highs to Can't assess is honest, but it isn't the same as getting them right.

## 7. What I couldn't verify or find

- **Not found:** any public, licensed, real, English, 2015-or-later corpus of commercial or transactional legitimate email. If it exists, it wasn't findable by web search.
- **Licence unclear (don't use until confirmed):** PrivacyMail (none applied, request-only), Princeton political emails, DataPhish (repo didn't load), IEEE DataPort multi-source, realprogrammersusevim, Tranco, Ugly Email tracker list, pihole email-tracker list, the Englehardt URL gist, kregg34, and the header-analyser repos. I didn't verify the Disconnect tracking list's licence, so I left it out.
- **Not read:** the Spanish Data in Brief dataset (the publisher blocked the fetch), the AURA PDF (no extractable text), and the Avocado LDC details.
- **Inference, not sourced:** the ham sizes and mix in section 5A, the effect sizes in step 5, and the seed-mailbox yield.
- The NHSJS study is in a student journal, and the arXiv preprints (2603.27326, 2606.11471, 2609.19873, 2511.21448) were not peer-reviewed at the time I checked.
