import aiohttp
import asyncio
import json
import logging
from aiohttp import ClientSession
from time import time

# Constants
THREAD_COUNT = 40
MAX_RETRIES = 3
CSRF_URL = 'https://www.instagram.com/accounts/login/?'
LOGIN_URL = "https://www.instagram.com/accounts/login/ajax/"

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class InstagramChecker:
    def __init__(self):
        self.session = None

    async def _get_csrftoken(self, session: ClientSession) -> str:
        """ Get the CSRF token required for the login request """
        try:
            async with session.get(CSRF_URL) as response:
                response.raise_for_status()
                return response.cookies.get('csrftoken', '')
        except Exception as e:
            logging.error(f"Error retrieving CSRF token: {e}")
            return ''

    async def _attempt_login(self, session: ClientSession, username: str, password: str, csrf_token: str) -> dict:
        """ Attempt to log into Instagram with given credentials """
        params = {
            "username": username,
            "enc_password": password,
            "queryParams": "{\"source\":\"auth_switcher\"}",
            "optIntoOneTap": "false"
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "x-csrftoken": csrf_token,
            "x-ig-app-id": "936619743392459",
            "x-instagram-ajax": "7ba5929a3456",
        }

        try:
            async with session.post(LOGIN_URL, headers=headers, data=params) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logging.error(f"Error during Instagram login attempt: {e}")
            return {"user": "False"}

    async def is_insta_acc(self, session: ClientSession, cred: str) -> dict:
        """ Check if an Instagram account exists based on the given number """
        csrf_token = await self._get_csrftoken(session)
        if not csrf_token:
            return {"user": "False"}

        retries = 0
        while retries < MAX_RETRIES:
            try:
                result = await self._attempt_login(session, cred, "", csrf_token)
                return result
            except Exception as e:
                logging.error(f"Attempt {retries + 1} failed for {cred}: {e}")
                retries += 1
                await asyncio.sleep(2)  # backoff before retrying

        return {"user": "False"}


class InstagramAccountChecker:
    def __init__(self, input_file: str, output_file: str, thread_count: int = THREAD_COUNT):
        self.input_file = input_file
        self.output_file = output_file
        self.thread_count = thread_count

    async def process_range(self, session: ClientSession, low_lim: int, high_lim: int):
        """ Process a range of phone numbers to check if they exist on Instagram """
        instagram_checker = InstagramChecker()
        for x in range(low_lim, high_lim + 1):
            logging.info(f"Checking number: +{x}")
            result = await instagram_checker.is_insta_acc(session, f"+{x}")
            if result.get("user") == "True":
                with open(self.output_file, "a+") as suc_file:
                    suc_file.write(f"+{x}\n")

    async def read_ranges(self):
        """ Read account ranges from the input file and return them as a list """
        ranges = []
        with open(self.input_file, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    low_lim, high_lim = map(int, line.split(":"))
                    ranges.append((low_lim, high_lim))
        return ranges

    async def start(self):
        """ Start the account checking process using asyncio """
        start_time = time()
        async with ClientSession() as session:
            ranges = await self.read_ranges()
            tasks = []
            for low_lim, high_lim in ranges:
                tasks.append(self.process_range(session, low_lim, high_lim))

            await asyncio.gather(*tasks)

        end_time = time()
        logging.info(f"Account checking completed in {end_time - start_time:.2f} seconds.")


if __name__ == "__main__":
    input_file = "list.txt"
    output_file = "success.txt"

    checker = InstagramAccountChecker(input_file, output_file)
    asyncio.run(checker.start())
