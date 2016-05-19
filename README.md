# plocker
A Linux command line password locker

This is a work in progress.

It is a Linux command line password locker. It creates a user based on your Linux user and stores passwords in an AES 256-bit encrypted file. Just login with one master password to retrieve your passwords.

Installation:

`git clone https://github.com/ArtificialImmunity/plocker/`

`cd plocker`

`sudo apt-get install -y $(cat dependencies)`

`pip install -r requirements`

Usage

`./plocker`

On first starting plocker, you will be prompted to make an account. This accounts username will be your Linux account username. There is only one plocker per Linux user allowed. The Locker is stored in the users home directory as '.Locker'.

Once you have an account, you can log in and follow the menu navigation to view,add, or, remove passwords in your Locker.

There is also an option to change your login password.
