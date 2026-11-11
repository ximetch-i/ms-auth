import boto3
from datetime import datetime

def lambda_handler(event, context):
    # Entrada (json)
    token = event['token']
    # Proceso
    tabla = boto3.resource('dynamodb').Table('t_tokens_acceso')
    response = tabla.get_item(Key={'token': token})
    if 'Item' not in response:
        return {'statusCode': 403, 'mensaje': 'Token no existe'}
    item = response['Item']
    if datetime.now().strftime('%Y-%m-%d %H:%M:%S') > item['expires']:
        return {'statusCode': 403, 'mensaje': 'Token expirado'}
    # Salida (json)
    return {'statusCode': 200, 'tenant_id': item['tenant_id'],
            'usuario_id': item['usuario_id'], 'rol': item['rol']}
