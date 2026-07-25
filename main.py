from flask import Flask, request, Response, jsonify
from datetime import datetime
import httpx
import warnings
import requests
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import MajorLogin_pb2
import MajorLogin_res_pb2
import urllib3

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ============ CONFIGURACOES ============
TOKEN_FILE = "token.txt"
PORT = 5000
CLIENT_VERSION = "OB54"
FREEFIRE_API = "https://client.us.freefiremobile.com"

# ============ CHAVES AES ============
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# ============ VARIAVEIS GLOBAIS ============
CACHED_JWT = None
CACHED_ACCOUNT_ID = None
CURRENT_TOKEN = None

# ============ FUNCOES ============
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def encrypt_packet(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def decode_jwt(jwt):
    """Decodifica JWT sem verificar assinatura e extrai account_id"""
    try:
        parts = jwt.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        padding = '=' * (4 - len(payload) % 4)
        payload += padding
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        return data
    except Exception as e:
        log(f"❌ Erro ao decodificar JWT: {e}")
        return None

def get_token_info(access_token):
    """Pega open_id e platform do token"""
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {
        "Accept": "*/*",
        "User-Agent": "GarenaMSDK/4.0.26.04212025 (iPhone14,3;ios - 18.4.1;en-MA;MA)"
    }
    
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    if response.status_code == 200:
        data = response.json()
        return {
            "open_id": data.get("open_id"),
            "platform": data.get("platform", "4"),
            "uid": data.get("uid"),
            "nickname": data.get("nickname")
        }
    return None

def create_major_login_pb(open_id, access_token, platform):
    """Cria request MajorLogin"""
    login = MajorLogin_pb2.MajorLogin()
    
    login.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode()
    login.game_name = "free fire"
    login.flag_5 = 1
    login.client_version = CLIENT_VERSION
    login.os_description = "Android OS 12 / API-31 (SP1A.210812.016/T505NDXS6CXB1)"
    login.device_form_factor = "Handheld"
    login.carrier = "we"
    login.connection_type = "WIFI"
    login.screen_width = 1334
    login.screen_height = 800
    login.dpi = "225"
    login.cpu_info = "ARM64 FP ASIMD AES | 4032 | 8"
    login.cpu_freq_khz = 2705
    login.gpu_vendor_model = "Adreno (TM) 610"
    login.gl_version = "OpenGL ES 3.2 V@0502.0 (GIT@5eaa426211, I07ee46fc66, 1633700387) (Date:10/08/21)"
    login.account_source_id = f"Google|{open_id}"
    login.ip_address = "154.183.6.12"
    login.locale = "pt"
    login.openid = open_id.encode()
    login.platform_type_23 = str(platform).encode()
    login.device_type_24 = "Handheld"
    login.device_model = "samsung SM-T505N"
    login.access_token = access_token.encode()
    login.flag_30 = 1
    login.carrier_41 = "we"
    login.connection_type_42 = "WIFI"
    login.checksum_57 = "e89b158e4bcf988ebd09eb83f5378e87".encode()
    login.metric_60 = 22394
    login.metric_61 = 1424
    login.metric_62 = 3349
    login.metric_63 = 24
    login.metric_64 = 1552
    login.metric_65 = 22394
    login.metric_66 = 1552
    login.metric_67 = 22394
    login.flag_73 = 1
    login.app_lib_path = "/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/lib/arm64"
    login.flag_76 = 2
    login.apk_signature_path = "b4d2689433917e66100ba91db790bf37|/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/base.apk"
    login.flag_78 = 2
    login.flag_79 = 2
    login.unknown_81 = "64"
    login.build_id = "2019115296"
    login.flag_85 = 1
    login.gl_renderer = "OpenGLES3"
    login.max_texture_size = 16383
    login.some_count_88 = 4
    login.city = "Damanhur"
    login.region_code = "BH"
    login.timezone_offset = 10800
    login.platform_str = "android_max"
    login.big_blob_94 = "KqsHTzpfADfqKnEg/KMctJLElsm8bN2M4ts0zq+ifY+560USyjMSDL386RFrwRloT0ZSbMxEuM+Y4FSvjghQQZXWWpY=".encode()
    login.large_metric_95 = 31095
    login.flag_97 = 1
    login.platform_type_99 = str(platform).encode()
    login.platform_type_100 = str(platform).encode()
    login.tzfield_102 = "".encode()
    
    return login.SerializeToString()

def parse_major_login_response(data):
    """Parseia resposta protobuf"""
    try:
        login_res = MajorLogin_res_pb2.MajorLoginRes()
        login_res.ParseFromString(data)
        return login_res
    except Exception as e:
        log(f"❌ Erro ao parsear resposta: {e}")
        return None

def get_cached_jwt_from_token(token):
    """Faz MajorLogin com um token e salva JWT + Account ID extraído do JWT"""
    global CACHED_JWT, CACHED_ACCOUNT_ID, CURRENT_TOKEN
    
    log(f"🔄 Obtendo JWT para token: {token[:30]}...")
    
    # Pega open_id e platform
    info = get_token_info(token)
    if not info or not info.get("open_id"):
        log("❌ Falha ao obter open_id do token")
        return None
    
    open_id = info["open_id"]
    platform = info["platform"]
    log(f"✅ Open ID: {open_id}")
    log(f"✅ Platform: {platform}")
    
    # Headers para MajorLogin
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": CLIENT_VERSION
    }
    
    payload = create_major_login_pb(open_id, token, int(platform))
    encrypted_payload = encrypt_packet(payload)
    
    try:
        response = requests.post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            headers=headers,
            data=encrypted_payload,
            verify=False,
            timeout=15
        )
        
        if response.status_code == 200:
            login_res = parse_major_login_response(response.content)
            
            if login_res and login_res.account_jwt:
                jwt = login_res.account_jwt
                
                log(f"✅ JWT obtido com sucesso!")
                log(f"📏 Tamanho do JWT: {len(jwt)} caracteres")
                
                # Extrai account_id do JWT
                decoded = decode_jwt(jwt)
                if not decoded:
                    log("❌ Falha ao decodificar JWT")
                    return None
                
                account_id = decoded.get("account_id")
                if not account_id:
                    log("❌ JWT não contém account_id")
                    return None
                
                log(f"🆔 Account ID extraído do JWT: {account_id}")
                
                # Atualiza variáveis globais
                CACHED_JWT = jwt
                CACHED_ACCOUNT_ID = account_id
                CURRENT_TOKEN = token
                
                # Salva token no arquivo
                with open(TOKEN_FILE, 'w') as f:
                    f.write(token)
                
                return {
                    "jwt": jwt,
                    "account_id": account_id
                }
            else:
                log("❌ Resposta não contém JWT")
                return None
        else:
            log(f"❌ Erro na requisição: {response.status_code}")
            log(f"Resposta: {response.content[:200]}")
            return None
            
    except Exception as e:
        log(f"❌ Erro: {e}")
        return None

def load_initial_token():
    """Carrega token do arquivo e obtém JWT"""
    global CURRENT_TOKEN
    
    try:
        with open(TOKEN_FILE, 'r') as f:
            token = f.read().strip()
            if not token:
                log("❌ token.txt está vazio!")
                return False
    except FileNotFoundError:
        log(f"❌ Arquivo {TOKEN_FILE} não encontrado!")
        return False
    
    CURRENT_TOKEN = token
    log(f"✅ Token carregado: {token[:30]}...")
    
    result = get_cached_jwt_from_token(token)
    return result is not None

# ============ ROTA CHANGE_TOKEN ============
@app.route('/change_token', methods=['GET'])
def change_token():
    """Muda o token e recarrega o JWT"""
    access_token = request.args.get('access_token')
    
    if not access_token:
        return jsonify({
            "success": False,
            "error": "Missing access_token parameter"
        }), 400
    
    log("="*50)
    log("🔄 ALTERANDO TOKEN...")
    
    result = get_cached_jwt_from_token(access_token)
    
    if result:
        return jsonify({
            "success": True,
            "message": "Token alterado com sucesso!",
            "jwt_size": len(result["jwt"]),
            "account_id": result["account_id"],
            "token": access_token[:30] + "..."
        })
    else:
        return jsonify({
            "success": False,
            "error": "Falha ao obter JWT para o novo token"
        }), 500

# ============ ROTA MAJORLOGIN ============
@app.route('/MajorLogin', methods=['POST'])
def major_login():
    global CACHED_JWT, CACHED_ACCOUNT_ID
    
    if not CACHED_JWT or not CACHED_ACCOUNT_ID:
        log("❌ JWT ou Account ID não carregados!")
        return Response("Proxy not initialized", status=500)
    
    try:
        # Monta headers manualmente
        headers = {
            "User-Agent": request.headers.get("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)"),
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": request.headers.get("Content-Type", "application/octet-stream"),
            "Expect": "100-continue",
            "X-GA": request.headers.get("X-GA", "v1 1"),
            "X-Unity-Version": request.headers.get("X-Unity-Version", "2018.4.11f1"),
            "ReleaseVersion": request.headers.get("ReleaseVersion", CLIENT_VERSION)
        }
        
        # Remove headers vazios
        headers = {k: v for k, v in headers.items() if v}
        
        body = request.get_data()
        
        log(f"📥 MajorLogin recebido: {len(body)} bytes")
        
        # Reencaminha para Garena
        with httpx.Client(timeout=30, verify=False) as client:
            response = client.post(
                "https://loginbp.ggpolarbear.com/MajorLogin",
                headers=headers,
                content=body
            )
        
        log(f"📤 Resposta da Garena: {response.status_code} - {len(response.content)} bytes")
        
        if response.status_code == 200:
            # Resposta é protobuf puro
            login_res = parse_major_login_response(response.content)
            
            if login_res:
                # Substitui o JWT e Account ID
                old_jwt = login_res.account_jwt
                old_account_id = login_res.account_id
                
                login_res.account_jwt = CACHED_JWT
                login_res.account_id = CACHED_ACCOUNT_ID
                
                log(f"🔄 Substituídos:")
                log(f"   JWT: {old_jwt[:30] if old_jwt else 'None'}... -> {CACHED_JWT[:30]}...")
                log(f"   Account ID: {old_account_id} -> {CACHED_ACCOUNT_ID}")
                
                # Serializa e retorna protobuf puro
                new_content = login_res.SerializeToString()
                
                resp = Response(new_content, status=200)
                resp.headers["Content-Type"] = "application/octet-stream"
                return resp
            else:
                log("❌ Falha ao parsear resposta")
                return Response(response.content, status=response.status_code)
        else:
            return Response(response.content, status=response.status_code)
            
    except Exception as e:
        log(f"❌ Erro: {e}")
        return Response(str(e).encode(), status=500)

# ============ ROTA PROXY UNIVERSAL ============
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def proxy(path):
    # Se for MajorLogin, já foi tratado pela rota específica
    if path.lower() in ['majorlogin', 'change_token', 'status']:
        return Response("Not Found", status=404)
    
    try:
        target_url = f"{FREEFIRE_API}/{path}" if path else FREEFIRE_API
        
        log(f"📥 Proxy: /{path} -> {target_url}")
        
        # Filtra headers sem depender da capitalização
        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            # Pula headers problemáticos
            if key_lower in {
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "keep-alive",
                "expect",
                "accept-encoding"
            }:
                continue
            # Pula Authorization vazio
            if key_lower == "authorization":
                if not value or value.strip() in ("", "Bearer", "Bearer "):
                    continue
            headers[key] = value
        
        with httpx.Client(timeout=30, verify=False) as client:
            response = client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=request.get_data(),
                params=dict(request.args) if request.args else None
            )
        
        log(f"📤 Proxy resposta: {response.status_code} - {len(response.content)} bytes")
        
        # Retorna resposta exata
        resp = Response(response.content, status=response.status_code)
        
        # Copia headers relevantes
        for key, value in response.headers.items():
            if key.lower() not in ['content-length', 'transfer-encoding', 'connection', 'keep-alive', 'date', 'server']:
                resp.headers[key] = value
        
        return resp
        
    except Exception as e:
        log(f"❌ Erro no proxy: {e}")
        return Response(str(e).encode(), status=500)

# ============ ROTA STATUS ============
@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "jwt_loaded": CACHED_JWT is not None,
        "jwt_size": len(CACHED_JWT) if CACHED_JWT else 0,
        "account_id": CACHED_ACCOUNT_ID,
        "current_token": CURRENT_TOKEN[:30] + "..." if CURRENT_TOKEN else None,
        "client_version": CLIENT_VERSION,
        "freefire_api": FREEFIRE_API
    })

# ============ INICIALIZACAO ============
if __name__ == '__main__':
    print("\n" + "="*60)
    print("PROXY - MAJORLOGIN JWT REPLACER")
    print("="*60)
    
    if load_initial_token():
        print("\n✅ Proxy pronto!")
        print(f"📡 Rodando em http://0.0.0.0:{PORT}")
        print(f"🔀 Rotas:")
        print(f"   /change_token?access_token=TOKEN -> Troca o token")
        print(f"   /MajorLogin -> Substitui JWT e Account ID")
        print(f"   /* -> Encaminha para {FREEFIRE_API}")
        print(f"   /status -> Status do proxy")
        print("="*60 + "\n")
        app.run(host='0.0.0.0', port=PORT, debug=False)
    else:
        print("\n❌ Falha na inicialização!")
        print(f"Verifique se o arquivo {TOKEN_FILE} existe e contém um Access Token válido.")
