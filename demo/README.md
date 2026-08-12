# FalconCTF Demo Challenge

This directory contains a demonstration challenge for the FalconCTF
Intelligent CTF Analysis Framework.

## Challenge

`competition_challenge.txt`

The file contains an encoded payload designed to demonstrate FalconCTF's
analysis pipeline.

## Run

./falconctf analyze demo/competition_challenge.txt

FalconCTF should:

1. Detect the Base64 encoded content.
2. Decode the payload.
3. Identify the decoded payload as a ZIP archive.
4. Export the decoded archive.
5. Classify the challenge.
6. Generate recommendations and a solve plan.
7. Produce a professional analysis report.

The exported payload can then be analyzed again with FalconCTF to continue
the investigation.
