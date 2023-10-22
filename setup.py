from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.view import view_config
from pyramid.authorization import ACLAuthorizationPolicy
import pymysql
import jwt
import datetime

# Koneksi ke database MySQL

connection = pymysql.connect(
    host='localhost',
    user='root',
    password='',
    db='pyramid-themovies',
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor
)

def auth_jwt_verify(request):
    authorization_header = request.cookies.get('token')
    if authorization_header:
        decoded_user = jwt.decode(authorization_header, 'secret', algorithms=['HS256'])
        with connection.cursor() as cursor:
            sql = "SELECT refresh_token FROM tokens WHERE user_id=%s"
            cursor.execute(sql, (decoded_user['sub'],))
            result = cursor.fetchone()
        if result:
            return decoded_user
        return None
    return None

@view_config(route_name='login', renderer='json')
def login(request):
    '''Create a login view
    '''
    auth_user = auth_jwt_verify(request)
    if auth_user:
        return {
            'greet': 'error',
            'message': 'Already logged in'
        }
    login = request.POST['login']
    password = request.POST['password']
    with connection.cursor() as cursor:
        sql = "SELECT * FROM users WHERE username=%s AND password=%s"
        cursor.execute(sql, (login, password))
        user = cursor.fetchone()
    if user:
        payload = {
            'sub': user['id'],
            'name': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=100)
        }
        encode = jwt.encode(payload, 'secret', algorithm='HS256')
        set_cookie = request.response.set_cookie('token', encode, max_age=100, httponly=True)
        with connection.cursor() as cursor:
            sql = "INSERT INTO tokens (user_id, refresh_token, jwt_token) VALUES (%s, %s, %s)"
            cursor.execute(sql, (user['id'], encode, 0))
            connection.commit()
        return {
            'greet': 'ok',
            'token': encode
        }
    else:
        return {
            'greet': 'error',
            'token': None
        }

@view_config(route_name='logout', renderer='json')
def logout(request):
    auth_user = auth_jwt_verify(request)
    if auth_user:
        with connection.cursor() as cursor:
            sql = "DELETE FROM tokens WHERE user_id=%s"
            cursor.execute(sql, (auth_user['sub'],))
            connection.commit()
            
        request.response.delete_cookie('token')
        return {
            'greet': 'ok',
            'message': 'Successfully logged out'
        }
    return {
        'greet': 'error',
        'message': 'Token not found'
    }

@view_config(route_name='hello', renderer="json")
def hello(request):
    auth_user = auth_jwt_verify(request)
    if auth_user:
        # show from table movies
        with connection.cursor() as cursor:
            sql = "SELECT * FROM movies"
            cursor.execute(sql)
            result = cursor.fetchall()
            
        data = {}
        for item in result:
            data[item['id']] = {
                'id': item['id'],
                'judul': item['judul'],
                'genre': item['genre'],
                'tahun': item['tahun'],
                'director': item['director'],
            }
        return {
            'greet': 'ok', 
            'name': auth_user['name'], 
            'data': data
            }
    else:
        request.response.status = 401  # Unauthorized
        return {'greet': 'Unauthorized', 'name': '', 'error': 'token not found'}

if __name__ == "__main__":
    with Configurator() as config:
        config = Configurator(settings={'jwt.secret': 'secret'})
        config.add_route('login', '/login')
        config.add_route('logout', '/logout')
        config.add_route('hello', '/welcome')
        config.scan()
        config.set_authorization_policy(ACLAuthorizationPolicy())
        config.add_static_view(name='static', path='static')
        config.include('pyramid_jwt')
        config.set_jwt_authentication_policy(config.get_settings()['jwt.secret'])
        
        app = config.make_wsgi_app()
    # Menjalankan aplikasi pada server lokal
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()