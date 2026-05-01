## Results Explained

This file explains what we found in plain language.



## The Real Numbers

These are the actual results from running John the Ripper on our Mac.

MD5 with dictionary attack: 33 out of 150 cracked in 4 seconds
MD5 with rule-based attack: 42 out of 150 cracked in 145 seconds
SHA-1 with dictionary attack: 33 out of 150 cracked in 2 seconds
SHA-1 with rule-based attack: 42 out of 150 cracked in 590 seconds
SHA-256 with dictionary attack: 33 out of 150 cracked in 2 seconds
SHA-256 with rule-based attack: 42 out of 150 cracked in 153 seconds
bcrypt cost 10 with dictionary attack: 17 out of 150 cracked in 300 seconds
bcrypt cost 12 with dictionary attack: 8 out of 150 cracked in 301 seconds
bcrypt cost 14 with dictionary attack: 2 out of 150 cracked in 315 seconds

---

## What This Means

Finding 1 - Common passwords are completely unsafe

All 30 common passwords were cracked instantly by the dictionary attack.
Passwords like "123456", "password", "qwerty", and "monkey" appear at the very top of the RockYou wordlist.
They are cracked in under 4 seconds no matter what algorithm is used.
This means that if you are using a common password, the only protection you have is the hashing algorithm, and even bcrypt cannot save you if your password is "123456".

Finding 2 - Swapping letters for symbols is not enough

The rule-based attack cracked 12 out of 30 human-modified passwords.
This is because John the Ripper's rule system already knows about common substitutions.
It knows that people replace "a" with "@", "o" with "0", "e" with "3", and so on.
So "P@ssw0rd" is not a creative password. It is a predictable pattern that attackers have already programmed into their tools.

Finding 3 - Passphrases and random passwords survived everything

Not a single passphrase or random password was cracked.
The passphrases are long enough that no dictionary or rule attack could reach them in the time limit.
The random passwords are completely unpredictable, so no wordlist or pattern can find them.

Finding 4 - MD5, SHA-1, and SHA-256 are equally bad

All three algorithms produced the exact same crack count: 42 passwords cracked.
This is a very important finding. Many people think that upgrading from MD5 to SHA-256 makes their system more secure.
It does not. All three algorithms are fast, which means an attacker can try millions of guesses per second against all three.
The bottleneck is not the algorithm, it is the speed.

Finding 5 - bcrypt cost factor makes a huge difference

bcrypt cost 10: 17 passwords cracked (11.3 percent)
bcrypt cost 12: 8 passwords cracked (5.3 percent)
bcrypt cost 14: 2 passwords cracked (1.3 percent)

The 2 passwords cracked at cost 14 were "123456" and "12345". These are at the very top of every wordlist and would be found almost immediately. Any password that is not at the top of the RockYou list would not be cracked at all with bcrypt cost 14 in the 5 minute time limit we used.

Finding 6 - bcrypt is 60,000 times slower than MD5

MD5 takes 0.021 milliseconds per hash.
bcrypt cost 14 takes 1,259 milliseconds per hash.

For a user logging in, a 1.2 second wait is barely noticeable.
For an attacker, this changes the throughput from millions of guesses per second to less than one per second.
This makes offline cracking of strong passwords effectively impossible with bcrypt cost 14.



## What We Recommend

For developers and organizations:
Use bcrypt with a cost factor of at least 12 for all password storage.
Never use MD5, SHA-1, or unsalted SHA-256 for passwords.
Always use a unique salt for each password even when using bcrypt, which does this automatically.

For users:
Use a passphrase of 4 or more random words, such as "coffee bridge lamp station".
Do not use common words with symbol substitutions like "P@ssw0rd".
Never use passwords that appear in common lists like "123456" or "password".
Use a password manager to generate truly random passwords.
Turn on two-factor authentication wherever possible.
