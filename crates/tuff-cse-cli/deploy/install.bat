@echo off
set BASE=C:\TUFF-CSE-TXN

if not exist %BASE% mkdir %BASE%
if not exist %BASE%\logs mkdir %BASE%\logs
if not exist %BASE%\sealed mkdir %BASE%\sealed
if not exist %BASE%\tmp mkdir %BASE%\tmp

copy cse_txn.exe %BASE%\cse_txn.exe
copy cse_txn.conf %BASE%\cse_txn.conf
copy bootstrap.hash %BASE%\bootstrap.hash

%BASE%\cse_txn.exe init --config %BASE%\cse_txn.conf --bootstrap-hash %BASE%\bootstrap.hash
%BASE%\cse_txn.exe selftest
pause
