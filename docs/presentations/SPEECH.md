# PrivacyGate AI — Group 21 presentation speech

Approximately two minutes at a steady speaking pace. Slide labels are cues, not spoken text.

**Slide 1 — Title**

Good morning, respected teacher and everyone present. I am Sambhav Surana from Group 21. Today, I am presenting PrivacyGate AI, a blockchain-based privacy-preserving IoT intelligence exchange.

**Slide 2 — Problem**

Industrial machines generate temperature, vibration and RPM readings. An external maintenance service may need an anomaly alert, but sharing every reading can expose sensitive operating information.

**Slide 3 — Objectives**

Our objective is to detect unusual machine behaviour while allowing the owner to control who receives the resulting insight.

**Slide 4 — Architecture**

A signed sensor simulator sends readings to a local gateway. The gateway stores encrypted data, runs anomaly detection and checks permissions against a local blockchain. The owner and reader receive different views.

**Slide 5 — Methodology**

The gateway first verifies each packet's signature, timestamp and sequence. It then encrypts the reading and checks for anomalies. Before sharing an insight, it verifies the reader's current permission.

**Slide 6 — Privacy**

AI detects unusual readings, while deterministic code enforces access. Owners can grant expiring permissions or revoke access. If blockchain state cannot be verified, third-party disclosure stops.

**Slide 7 — Demonstration**

The owner sees detailed measurements. The reader decrypts only a restricted anomaly event, without raw sensor values.

**Slide 8 — AI results**

We use Isolation Forest, trained on 512 synthetic normal readings. It detected all 128 test anomalies, with five false positives. The rule baseline performed better on this synthetic dataset, so real equipment evaluation remains necessary.

**Slide 9 — Validation**

The recorded report includes 28 passing Python tests and 11 passing browser cases, covering checks such as tampering, replay and revocation.

**Slide 10 — Conclusion**

The project demonstrates controlled sharing of encrypted IoT insights. Future work includes real equipment data, reviewed model retraining and stronger key management.

Thank you. I am ready for your questions.
