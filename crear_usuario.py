import boto3
from comun import hash_password

def lambda_handler(event, context):
    # Entrada (json): la Lambda se invoca directo, sin 'body'
    tenant_id = event.get('tenant_id')
    usuario_id = event.get('usuario_id')
    password = event.get('password')
    rol = event.get('rol', 'MIEMBRO')
    if not (tenant_id and usuario_id and password):
        return {'statusCode': 400, 'mensaje': 'Faltan tenant_id, usuario_id o password'}
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
    return {'statusCode': 200, 'usuario_id': usuario_id}
