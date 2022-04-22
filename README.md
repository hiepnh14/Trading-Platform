# Stock Trading Website 
## Project description: 
A project from CS50 Introduction to Computer Science. 
This website is a financial platform that allows users to register, query, buy and sell stocks.
The data for the price of the stocks are updated in real-time using IEX.
## Structure:

### Front-end:
From the homepage, users can access to: 
- register,
- log in,
- log out,
- see their portfolios,
- query stock's price,
- buy/sell stocks,
- see history,
- change their profile, deposit/withdraw cash.

### Back-end:
- It allows users to buy/sell stocks and store the transaction in history, change their profiles and accounts.
- All user data including their accounts, transactions history,... are stored in a SQL file (finance.db).
- Users passwords can be changed are encrypted for security.
## Instruction:
- Install the packages in requirement.txt
- Initializing step: Take a token from the following URL: https://cloud-sse.iexapis.com/stable/stock/nflx/quote?token=API_KEY
- Activate the API key:
```
$ export API_KEY=value
```
- Run: Start Flask's built-in web server:
```
$ flask fun
```
The finance.db database includes 3 tables: 
```
"stock": users' portfolios (id, stock, amount), 
"users": users' accounts (id, username, encrypted password, balance), 
"trans": transactions history (id, stock, transaction amount, price/item, time).
```
For more information: Visit [CS50/Finance](https://cs50.harvard.edu/x/2022/psets/9/finance/)

## Author
- [Hiep Nguyen](https://github.com/hiepnh14)
