import requests
import json
from flask import Flask, redirect, render_template, request, Response, jsonify


app = Flask(__name__)
url = "http://agroportal.track.uz"


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/login")
def login():
    auth_token = request_sso_authorization_request()
    print(auth_token)
    # TODO write auth token to session
    if auth_token.startswith('error'):
        return 'error'

    return redirect(f"{url}/login/?sso={auth_token}")


@app.route("/logout")
def logout():
    pass


@app.route("/sso/accept")
def sso_accept():
    res = get_sso_authorization_request(sso_token='')


@app.route("/sso/deauthenticate")
def sso_deauthenticate():
    pass


@app.route("/sso/event")
def sso_event():
    print(request)
    if request.method != 'POST':
        return Response(status=405)

    try:
        data = json.loads(request.body.decode('utf8'))
        print('!'*66, data)
    except:
        return Response(status=400)

    if (
        not data.get('token', '').strip()
        or data.pop('token') != 'token'  # check to == with token from .env
    ):
        return jsonify({
            'error': ('Token not provided or incorrect')
        })

    if not data.get('type', '').strip():
        return jsonify({'error': ('Event type field not set')})

    try:
        type_name = str(data.pop('type')).strip()

        if type_name.startswith('_'):
            return jsonify({'error': ('Incorrect event type name')})
    except:
        pass
    #     module_name, class_name = getattr(
    #         settings,
    #         'SSO_EVENT_ACCEPTOR_CLASS',
    #         'django_sso.sso_service.backend.EventAcceptor'
    #     ).rsplit('.', 1)

    #     dispatcher_class = getattr(importlib.import_module(module_name), class_name)

    #     if not hasattr(dispatcher_class, type_name):
    #         return JsonResponse({'error': f"{_('Event type not supported')} ({type_name})"})
    #     else:
    #         try:
    #             getattr(dispatcher_class(), type_name)(**data)
    #         except Exception as e:
    #             return JsonResponse({'error': str(e)})

    #         return JsonResponse({'ok': True})

    # except Exception as e:
    #     return JsonResponse({'error': str(e)})


def request_sso_authorization_request():
    """
    Запрашивает токен авторизации на SSO-шлюзе и возвращает его как результат.
    Необходим для дальнейшей авторизации пользователя на шлюзе авторизации
    """
    try:
        result = requests.post(url + '/sso/obtain/', {
            "token": 'token',
            "next_url": '/next_url/',
        })

        if result.status_code != 200:
            raise Exception(
                f'Некорректный ответ сервера авторизации: STATUS={result.status_code}; TEXT={result.text}')

        result = result.json()
    except Exception as e:
        raise Exception('error while request sso/obtain')

    if 'token' in result:
        return result['token']
    else:
        return f'error: {result["error"]}'

def get_sso_authorization_request(sso_token: str) -> dict:
    """
    Get SSO token information from server to check authorization
    """
    url = "http://agroportal.track.uz"
    try:
        result = requests.post(url + '/sso/get/', {
            'token': 'client token',
            'authentication_token': 'auth_token from session'
        })

        if result.status_code != 200:
            return f'Некорректный ответ сервера авторизации: STATUS={result.status_code}; TEXT={result.text}'

        result = result.json()

        if 'error' in result:
            return result['error']
    except Exception as e:
        print('error')
        return

    return result