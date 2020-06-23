import os.path

def cert_path(filename):
    return os.path.join(os.path.dirname(__file__), 'certs', filename)
