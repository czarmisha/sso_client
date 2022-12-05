import requests, json, os
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, Response, jsonify, session
from flask_session import Session


dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

token = os.environ['SSO_TOKEN']
url = os.environ['SSO_SERVER_URL']
app = Flask(__name__)
app.config.update(SECRET_KEY=os.urandom(24))
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/login")
def login():
    auth_token = request_sso_authorization_request()
    session['auth_token'] = auth_token
    if auth_token.startswith('error'):
        return 'error'
    return redirect(f"{url}/login/?sso={auth_token}")


@app.route("/logout")
def logout():
    # if not request.user.is_anonymous:
    try:
        logout = request_deauthentication(request.user)
        if logout:
            del session['user']
            del session['auth_token']
        #TODO make logout
    except Exception as e:
        return render_template('error.html', error=e)

    return redirect('/')


@app.route("/sso/accept/")
def sso_accept():
    res = get_sso_authorization_request(sso_token=session['auth_token'])
    if 'error' in res:
        return res['error']
    if 'authenticated' in res and res['authenticated']==True:
        session['user'] = res['user_identy']
    make_used = set_sso_authorization_request_used(sso_token=session['auth_token'])
    if make_used:
        return render_template('success.html', user=session['user'])
    else:
        return render_template('success.html', error='error')


# @app.route("/sso/deauthenticate")
# def sso_deauthenticate():
#     pass


@app.route("/sso/event")
def sso_event():
    # TODO save user
    if request.method != 'POST':
        return Response(status=405)

    try:
        data = json.loads(request.body.decode('utf8'))
    except:
        return Response(status=400)

    if (
        not data.get('token', '').strip()
        or data.pop('token') != token  # check to == with token from .env
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


def request_sso_authorization_request():
    """
    Запрашивает токен авторизации на SSO-шлюзе и возвращает его как результат.
    Необходим для дальнейшей авторизации пользователя на шлюзе авторизации
    """
    try:
        result = requests.post(url + '/sso/obtain/', {
            "token": token,
            "next_url": '/next_url/',
        })

        if result.status_code != 200:
            raise Exception(
                f'Некорректный ответ сервера авторизации: STATUS={result.status_code}; TEXT={result.text}')

        result = result.json()
    except Exception as e:
        raise Exception('error while request sso/obtain', e)

    if 'token' in result:
        return result['token']
    else:
        return f'error: {result["error"]}'


def get_sso_authorization_request(sso_token: str) -> dict:
    """
    Get SSO token information from server to check authorization
    """
    try:
        result = requests.post(url + '/sso/get/', {
            'token': token,
            'authentication_token': sso_token
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


def set_sso_authorization_request_used(sso_token):
    """
    For sso_service side. Makes SSO request as used for
    authentication procedure (not available for next authentications)
    """
    try:
        result = requests.post(url + '/sso/make_used/', {
            'token': token,
            'authentication_token': sso_token
        })

        if result.status_code != 200:
            raise Exception(
                f'Некорректный ответ сервера авторизации: STATUS={result.status_code}; TEXT={result.text}'
            )
        result = result.json()
        if result['ok']:
            return True
        else:
            return False
    except Exception as e:
        return False


def request_deauthentication(user):
    """
    Call SSO sso_gateway to deauthorize user everywhere
    """
    try:
        result = requests.post(url + '/sso/deauthenticate/', {
            'token': token,
            'user_identy': user
        })

        if result.status_code != 200:
            raise Exception(f'Некорректный ответ сервера авторизации: STATUS={result.status_code}; TEXT={result.text}')

        result = result.json()

        if 'error' in result:
            raise Exception(result['error'])
        if 'ok' in result:
            return result['ok']
    except Exception as e:
        raise Exception(e)