# Evaluating Password Security Using Hash Cracking Techniques

**Authors:** Aditya Dev and Aditya Chauhan
**Course:** Introduction to Cybersecurity
**Date:** April 2026



## What This Project Does

This project studies how easy or hard it is to crack passwords depending on two things:

1. How the password is built (common, modified, passphrase, random, etc.)
2. How the password is stored (MD5, SHA-1, SHA-256, bcrypt, etc.)

We built a dataset of 150 passwords, hashed them using 7 different methods, then used a real password cracking tool called John the Ripper to try to crack them. We recorded the results and made charts showing what we found.



## What Is Inside This Folder


password_project/

    README.md                   This file. Start here.

    scripts/                    All Python and Bash scripts

        step1_generate_passwords.py

        step2_generate_hashes.py

        step3_run_john.sh
        
        step4_analyze_results.py

    passwords/                  Generated after running Step 1

    hashes/                     Generated after running Step 2

    results/                    Generated after running Step 3

    graphs/                     Charts generated after running Step 4

    docs/                       Extra documentation

        SETUP.md                How to install everything

        HOW_IT_WORKS.md         Simple explanation of every script

        RESULTS.md              What our results mean




## How to Run This Project (Quick Version)

Step 1. Install everything (see docs/SETUP.md for details)

Step 2. Open Terminal and go to this folder:

cd ~/Desktop/password_project

Step 3. Run each script in order:

python3 scripts/step1_generate_passwords.py

python3 scripts/step2_generate_hashes.py

bash scripts/step3_run_john.sh ~/rockyou.txt

python3 scripts/step4_analyze_results.py


Step 4. Look at the graphs folder for your results.



## Key Findings

- Common passwords like "123456" and "password" were cracked 100 percent of the time
- Human-modified passwords like "P@ssw0rd" were cracked 40 percent of the time using rule-based attacks
- Passphrases and random passwords were never cracked
- MD5, SHA-1, and SHA-256 all had the same crack rate of 28 percent
- bcrypt at cost 14 had a crack rate of only 1.3 percent
- bcrypt is 60,000 times slower than MD5 to compute, which is what makes it secure



## Tools Used

- Python 3 for generating passwords and hashes
- John the Ripper for cracking
- RockYou wordlist as the dictionary
- Matplotlib and Pandas for charts and analysis
