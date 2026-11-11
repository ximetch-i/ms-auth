import boto3
import uuid
from datetime import datetime, timedelta
from comun import hash_password

def lambda_handler(event, context):
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
