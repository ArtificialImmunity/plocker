# plocker
A Linux command line password locker

This is a work in progress.

It is a Linux command line password locker. It creates a user based on your Linux user and stores passwords in an AES 256-bit encrypted file. Just login with one master password to retrieve your passwords.

Installation:

`sudo apt-get install python python-dev python-pip build-essential libffi-dev libssl-dev git`

`git clone https://github.com/ArtificialImmunity/plocker/`

`cd plocker`

`pip install -r requirements`

Usage

`./plocker`
