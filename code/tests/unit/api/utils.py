def get_headers(jwt, auth_type='Bearer', content_type='application/json'):
    headers = {'Authorization': f'{auth_type} {jwt}'}
    if content_type:
        headers['Content-Type'] = content_type
    return headers