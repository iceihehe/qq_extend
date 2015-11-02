# -*- coding=utf-8 -*-
# Created Time: 2015年11月02日 星期一 15时14分29秒
# File Name: basic.py

import requests
import json
import urllib


class QQBasic(object):
    """
    百度基本功能类

    其实现在我只用了天气接口
    """
    def __init__(self, appid, appsecret, redirect_uri):

        self._appid = appid
        self._appsecret = appsecret
        self._redirect_uri = redirect_uri

    def _post(self, url, **kwargs):
        """
        使用POST方法发请求
        """

        return self._request(
            method="post",
            url=url,
            **kwargs
        )

    def _get(self, url, **kwargs):
        """
        使用GET方法发请求
        """

        return self._request(
            method='get',
            url=url,
            **kwargs
        )

    def _request(self, method, url, **kwargs):
        """
        发送请求
        """

        if isinstance(kwargs.get("data", ""), dict):
            body = json.dumps(kwargs["data"], ensure_ascii=False)
            body = body.encode('utf8')
            kwargs["data"] = body

        r = requests.request(
            method=method,
            url=url,
            **kwargs
        )
        r.raise_for_status()
        response_json = r.json()
        self._check_official_error(response_json)
        return response_json

    def _check_official_error(self, json_data):
        """
        检测官方错误
        """
        if "error" in json_data and json_data["error"] != 0:
            raise EOFError(
                "{}: {}".format(json_data["error"], json_data["status"])
            )

    @classmethod
    def get_authorize_url(cls, appid, redirect_uri, state=123456, scope=None):
        url = ('https://graph.qq.com/oauth2.0/authorize?'
               'client_id={0}&response_type=code&redirect_uri={1}&state={2}')
        url = url.format(appid, urllib.quote(redirect_uri), state)
        if scope:
            url = url + '&scope=' + scope

        return url

    def get_access_token(self, code):

        return self._get(
            url='https://graph.qq.com/oauth2.0/token',
            params={
                'grant_type': 'authorization_code',
                'client_id': self._appid,
                'client_secret': self._appsecret,
                'code': code,
                'redirect_uri': self._redirect_uri,
            },
        )

    def get_user_info(self, access_token, openid):
        """获取用户基本信息"""

        return self._get(
            url='https://graph.qq.com/user/get_user_info',
            params={
                'access_token': access_token,
                'oauth_consumer_key': self._appid,
                'openid': openid,
            },
        )

    def set_access_token(self, access_token):
        """添加access_token"""

        self._access_token = access_token

    def get_openid(self):
        """用access_token换取用户openid"""

        return self._get(
            url='https://graph.qq.com/oauth2.0/me',
            params={
                'access_token': self._access_token,
            },
        )
