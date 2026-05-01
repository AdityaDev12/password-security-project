# How It Works

This file explains what each script does in simple terms.


## Step 1 - step1_generate_passwords.py

What it does:
This script creates 150 fake passwords organized into 5 groups of 30.

The 5 groups are:

Group 1 - Common passwords
These are real passwords that show up constantly in leaked databases.
Examples: 123456, password, qwerty, iloveyou, monkey

Group 2 - Human-modified passwords
These are common words where people have swapped letters for symbols or numbers.
This is what most people think makes a password strong.
Examples: P@ssw0rd, S3cur1ty!, L3tm31n!

Group 3 - Short complex passwords
These are 6 characters long and use uppercase, lowercase, numbers, and symbols.
They look strong but are short.
Examples: aB3!xY, Zk9@mP

Group 4 - Passphrases
These are 4 to 6 common words strung together with spaces.
They are long and easy to remember.
Examples: correct horse battery staple, my cat loves sunny days

Group 5 - Random high-entropy passwords
These are 16-character passwords generated randomly with no pattern at all.
Examples: aZ3!bYXk8@cPVm2#

How to run it:

python3 scripts/step1_generate_passwords.py


What it creates:
A folder called passwords with 5 text files, one per group, and one master file with all 150 passwords.



## Step 2 - step2_generate_hashes.py

What it does:
This script takes every password from Step 1 and runs it through 7 different hashing algorithms.

What is a hash?
A hash is a scrambled version of a password. When you log in to a website, the site does not store your actual password. It stores a hash. When you type your password, it hashes it and checks if it matches the stored hash.

The 7 algorithms we test:

MD5: Very old and fast. Takes 0.02 milliseconds per hash.
SHA-1: Old and fast. Takes 0.004 milliseconds per hash.
SHA-256: Newer but still fast. Takes 0.004 milliseconds per hash.
Salted SHA-256: Same as SHA-256 but adds a random extra string before hashing. Harder to attack.
bcrypt cost 10: Slow by design. Takes 79 milliseconds per hash.
bcrypt cost 12: Even slower. Takes 315 milliseconds per hash.
bcrypt cost 14: Very slow. Takes 1259 milliseconds per hash.

The slowness of bcrypt is the whole point. A user logging in waits about 1 second. An attacker trying millions of guesses is slowed from millions per second to less than 1 per second.

How to run it:

python3 scripts/step2_generate_hashes.py


Important: This will take about 15 to 20 minutes because of bcrypt. Do not close the terminal. You will see progress every 10 passwords.

What it creates:
A folder called hashes with one file for each algorithm, ready for John the Ripper.
Also a file called hashing_times.json with exact timing data.



## Step 3 - step3_run_john.sh

What it does:
This script runs John the Ripper to try to crack every hash file we created in Step 2.

What is John the Ripper?
John the Ripper is a tool used by security professionals to test whether passwords are strong. It tries millions of guesses per second to find the original password from a hash.

The 4 attack types we use:

Dictionary attack: Tries every word in the RockYou wordlist one by one.
Rule-based attack: Takes every word in RockYou and mutates it. For example it tries "password", then "Password", then "p@ssword", then "PASSWORD", and so on.
Hybrid attack: Combines wordlist words with number and symbol patterns.
Mask attack: Tries every combination matching a specific pattern like one capital letter, three lowercase, two digits.

Each attack runs for a maximum of 5 minutes.

How to run it:

bash scripts/step3_run_john.sh ~/rockyou.txt


This will take about 30 to 45 minutes total. Let it run completely.

What it creates:
A folder called results with .pot files for each attack. A .pot file lists every hash that was cracked and what the original password was.

---

## Step 4 - step4_analyze_results.py

What it does:
This script reads the .pot files from Step 3, figures out which passwords were cracked and which category they belong to, then makes 5 charts and a summary table.

The 5 charts it makes:

Chart 1 - Crack rate by password category
Shows which type of password was easiest to crack.

Chart 2 - Crack rate by hashing algorithm
Shows how much protection each algorithm actually provided.

Chart 3 - Dictionary vs rule-based attack effectiveness
Shows which attack type worked better against each algorithm.

Chart 4 - Hashing time per algorithm
Shows how slow each algorithm is on a log scale. This explains why bcrypt is so much more secure.

Chart 5 - Password length vs crack resistance
Shows whether longer passwords survived better.

How to run it:
```
python3 scripts/step4_analyze_results.py
```

What it creates:
5 PNG chart files and a CSV summary table, all saved in the graphs folder.
