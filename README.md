# py-REST-API

# FastAPI Cryptocurrency Tracker

## Overview

This project is a cryptocurrency price tracker web app built using FastAPI as the backend, SQLite as the database, and CoinCap API for fetching cryptocurrency prices.

## Features

- User authentication (signup, signin, signout)
- Tracked coins management (add, remove)
- Displaying a list of tracked coins with prices in Rupiah (IDR)

## Getting Started

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/adhiesg/py-REST-API
   cd py-REST-API

2. Create and activate virtual env:

    ```bash
    python -m venv venv
    ```

    Unix/Linux
    ```bash
    source venv/bin/activate
    ```

    Windows
    ```bash
    .\venv\Scripts\activate
    ```

3. Install depedencies

    pip install -r requirements.txt

4. Setup SQLite database

    alembic upgrade head

5. Run the FASTAPI application

    uvicorn main:app --reload

### Usage
Open the Swagger documentation at http://127.0.0.1:8000/docs to explore and test the available API endpoints.

Use the authentication endpoints (/signup, /signin, /signout) to manage user sessions.

Use the tracked coins endpoints (/listcoin, /addcoin, /removecoin, /usertrackedcoins) to manage tracked cryptocurrencies.

### API Endpoints
Signup: /signup - Register a new user.
Signin: /signin - Authenticate and obtain a JWT token.
Signout: /signout - Deauthenticate and remove the JWT token.
List Coin: /listcoin - To show available cryptocurrency list to track
Add Coin: /addcoin - Add a new cryptocurrency to the tracked list by coin id.
Remove Coin: /removecoin - Remove a cryptocurrency from the tracked list by coin id.
User Tracked Coins: /usertrackedcoins - Retrieve the list of tracked coins for the authenticated user.




