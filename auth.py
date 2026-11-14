# Lambda Auth (ms-auth). Una sola Lambda atiende varios endpoints.
# API Gateway (integration: lambda) manda en "requestPath" la ruta del recurso.
import boto3
import json
import uuid
from comun import hash_password
from datetime import datetime, timedelta


def login_usuario(event, context):
    # Entrada (json)
    body = event['body']
    tenant_id = body.get('tenant_id')
    usuario_id = body.get('usuario_id')
    password = body.get('password')
    if not (tenant_id and usuario_id and password):
        return {'statusCode': 400, 'mensaje': 'Faltan tenant_id, usuario_id o password'}
    # Proceso
    dynamodb = boto3.resource('dynamodb')
    usuarios = dynamodb.Table('t_usuarios')
    response = usuarios.get_item(Key={'tenant_id': tenant_id, 'usuario_id': usuario_id})
    if 'Item' not in response or response['Item']['password'] != hash_password(password):
        return {'statusCode': 403, 'mensaje': 'Usuario o password incorrecto'}
    usuario = response['Item']
    token = str(uuid.uuid4())
    expires = (datetime.now() + timedelta(minutes=60)).strftime('%Y-%m-%d %H:%M:%S')
    dynamodb.Table('t_tokens_acceso').put_item(Item={
        'token': token,
        'tenant_id': tenant_id,
        'usuario_id': usuario_id,
        'rol': usuario['rol'],
        'expires': expires
    })
    # Salida (json)
    return {'statusCode': 200, 'token': token, 'tenant_id': tenant_id,
            'usuario_id': usuario_id, 'rol': usuario['rol']}


ROLES = ('ADMIN', 'GERENTE', 'MIEMBRO')


NO_AUTORIZADO = {'statusCode': 403, 'mensaje': 'Forbidden - Acceso No Autorizado'}


def crear_usuario(event, context):
    # Proteger el Lambda: token en el header Authorization
    headers = {k.lower(): v for k, v in (event.get('headers') or {}).items()}
    token = headers.get('authorization')
    if not token:
        return NO_AUTORIZADO
    r = boto3.client('lambda').invoke(FunctionName='ValidarTokenAcceso',
                                      InvocationType='RequestResponse',
                                      Payload=json.dumps({'token': token}))
    sesion = json.loads(r['Payload'].read())
    if sesion.get('statusCode') != 200:
        return NO_AUTORIZADO
    if sesion['rol'] != 'ADMIN':
        return {'statusCode': 403, 'mensaje': 'Solo un ADMIN puede crear usuarios'}
    # El usuario se crea siempre en el tenant del token
    tenant_id = sesion['tenant_id']
    # Entrada (json)
    body = event.get('body') or {}
    usuario_id = body.get('usuario_id')
    password = body.get('password')
    rol = body.get('rol', 'MIEMBRO')
    if not (usuario_id and password) or rol not in ROLES:
        return {'statusCode': 400,
                'mensaje': 'Falta usuario_id o password, o el rol no es valido: ' + ', '.join(ROLES)}
    # Proceso
    tabla = boto3.resource('dynamodb').Table('t_usuarios')
    try:
        tabla.put_item(
            Item={'tenant_id': tenant_id, 'usuario_id': usuario_id,
                  'password': hash_password(password), 'rol': rol},
            ConditionExpression='attribute_not_exists(tenant_id)'
        )
    except tabla.meta.client.exceptions.ConditionalCheckFailedException:
        return {'statusCode': 409, 'mensaje': 'El usuario ya existe'}
    # Salida (json)
    return {'statusCode': 200, 'tenant_id': tenant_id, 'usuario_id': usuario_id, 'rol': rol}


RUTAS = {
    '/auth/login': login_usuario,
    '/auth/crear-usuario': crear_usuario,
}

def lambda_handler(event, context):
    ruta = (event or {}).get('requestPath')
    funcion = RUTAS.get(ruta)
    if funcion is None:
        return {'statusCode': 404, 'mensaje': 'Ruta no encontrada: %s' % ruta}
    return funcion(event, context)
