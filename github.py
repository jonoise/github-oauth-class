import os
import aiohttp
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model


class Github:
    """
    Github class to fetch the user info and return it
    """

    @staticmethod
    async def get_user_authorization():
        headers = {
            "content-type": "application/json",
            "Access-Control-Expose-Headers": "ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval"
        }
        async with aiohttp.ClientSession() as session:
            url = "https://github.com/login/oauth/authorize"
            async with await session.get(url, headers=headers) as res:
                data = await res.json()
                return data

    @staticmethod
    async def request_access_token(code):
        GITHUB_ID = os.environ.get('GITHUB_ID')
        GITHUB_SECRET = os.environ.get('GITHUB_SECRET')
        async with aiohttp.ClientSession() as session:
            url = "https://github.com/login/oauth/access_token"
            params = {
                "client_id": GITHUB_ID,
                "client_secret": GITHUB_SECRET,
                "code": code,
            }
            headers = {
                "content-type": "application/json",
                "accept": "application/json",
                "Access-Control-Expose-Headers": "ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval"
            }
            async with session.post(url, headers=headers, params=params) as res:
                data = await res.json()
                return data

    @staticmethod
    async def get_user_details(access_token):
        headers = {
            "Authorization": f"token {access_token}",
            "content-type": "application/json",
            "Access-Control-Expose-Headers": "ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval"
        }
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.github.com/user"
                async with await session.get(url, headers=headers) as res:
                    data = await res.json()
                    return {
                        "username": data.get('login'),
                        "user_id": data.get('id'),
                        "image": data.get('avatar_url'),
                        "github_url": data.get('html_url'),
                        "location": data.get('location')}
        except:
            return {"message": "The token is invalid or expired."}

    async def get_user_email(access_token):
        """
        validate method of fetching data
        """
        headers = {
            "Authorization": f"token {access_token}",
            "content-type": "application/json",
            "Access-Control-Expose-Headers": "ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval"
        }
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.github.com/user/emails"
                async with await session.get(url, headers=headers) as res:
                    data = await res.json()
                    # El return es el email en formato string.
                    return data[0].get('email')
        except:
            return {"message": "The token is invalid or expired."}

    @staticmethod
    def register_or_authenticate(data):

        registered_user = get_user_model().objects.filter(
            email=data['email']).first()

        # Si no encontramos el usuario por e-mail, lo buscamos por username:
        if not registered_user:
            registered_user = get_user_model().objects.filter(
                username=data['username']).first()

        if registered_user:
            registered_user.github_access_token = data['access_token']
            registered_user.save()
            authenticated_user = authenticate(
                email=registered_user.email, password=os.environ.get('GITHUB_SECRET_PASSWORD'))

            return {
                "message": "user logged in",
                'id': authenticated_user.pk,
                'tokens': authenticated_user.tokens(),
            }

        newUser = get_user_model().objects.create_user(
            email=data['email'],
            password=os.environ.get('GITHUB_SECRET_PASSWORD'),
            username=data['username'])
        newUser.github_access_token = data['access_token']
        newUser.github_id = data['id']
        newUser.provider = 'github'
        newUser.profile.image = data['image']
        newUser.profile.name = data['name']
        newUser.profile.save()
        newUser.save()

        authenticated_user = authenticate(
            email=newUser.email, password=os.environ.get('GITHUB_SECRET_PASSWORD'))

        return {
            'id': authenticated_user.pk,
            'tokens': authenticated_user.tokens(),
        }
