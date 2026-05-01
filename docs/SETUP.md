# Setup Guide

This guide walks you through installing everything you need to run this project on a Mac.



## Step 1 - Install Homebrew

Homebrew is a tool that lets you install software on Mac from the terminal.
Open your Terminal app and paste this:


/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"


After it finishes, also run this so your terminal can find Homebrew:


echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"


Note: If you have an older Intel Mac, you may not need the second command.



## Step 2 - Install John the Ripper

John the Ripper is the password cracking tool we use in Step 3.


brew install john-jumbo


To check it installed correctly, run:


john


You should see a help message with version 1.9.0-jumbo or similar.



## Step 3 - Install Coreutils

This gives your Mac the "timeout" command that our Step 3 script uses.


brew install coreutils




## Step 4 - Install Python Libraries

We use three Python libraries: bcrypt for hashing, matplotlib for charts, and pandas for data tables.


pip3 install bcrypt matplotlib pandas --break-system-packages


If that gives an error, try:


python3 -m pip install bcrypt matplotlib pandas


---

## Step 5 - Download the RockYou Wordlist

RockYou is a list of over 14 million real passwords from a 2009 data breach.
It is the standard wordlist used in password security research.


curl -L -o ~/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt


This file is about 133 MB so it may take a minute to download.

---

## Step 6 - Verify Everything is Ready

Run these commands to make sure everything is installed:


john
python3 --version
ls ~/rockyou.txt


If all three work without errors, you are ready to run the project.



## Common Problems

Problem: "brew: command not found"
Solution: Homebrew did not install correctly. Try the install command again.

Problem: "john: command not found"
Solution: Run "brew install john-jumbo" again.

Problem: "No module named bcrypt"
Solution: Run "pip3 install bcrypt --break-system-packages"

Problem: "timeout: command not found"
Solution: Run "brew install coreutils"

Problem: rockyou.txt not found
Solution: Run the curl download command again and wait for it to finish.
