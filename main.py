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
PORT = 5001
CLIENT_VERSION = "OB54"
FREEFIRE_API = "https://client.us.freefiremobile.com"

# ============ CHAVES AES ============
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# ============ VARIAVEIS GLOBAIS ============
CACHED_RESPONSE = None  # Resposta completa do MajorLogin (protobuf)
CACHED_DATA = {}  # Dados extraídos para debug
CURRENT_TOKEN = None

# ============ FUNCOES ============
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def encrypt_packet(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def decode_jwt(jwt):
    """Decodifica JWT sem verificar assinatura"""
    try:
        parts = jwt.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        padding = '=' * (4 - len(payload) % 4)
        payload += padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
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

def fetch_major_login_response(token):
    """Faz MajorLogin e retorna a resposta completa"""
    log(f"🔄 Obtendo resposta MajorLogin para token: {token[:30]}...")
    
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
            log(f"✅ Resposta obtida: {len(response.content)} bytes")
            
            # Parseia para extrair dados de debug
            login_res = parse_major_login_response(response.content)
            if login_res:
                CACHED_DATA["jwt"] = login_res.account_jwt[:30] + "..." if login_res.account_jwt else None
                CACHED_DATA["account_id"] = login_res.account_id
                CACHED_DATA["uid"] = login_res.uid
                CACHED_DATA["region"] = login_res.region
                
                # Extrai account_id do JWT
                if login_res.account_jwt:
                    decoded = decode_jwt(login_res.account_jwt)
                    if decoded:
                        CACHED_DATA["jwt_account_id"] = decoded.get("account_id")
                
                log(f"   Account ID: {login_res.account_id}")
                log(f"   UID: {login_res.uid}")
                log(f"   Region: {login_res.region}")
                log(f"   Country: {login_res.country_code}")
                log(f"   JWT: {login_res.account_jwt[:30] if login_res.account_jwt else 'None'}...")
            
            # Salva a resposta COMPLETA (o clone)
            return response.content
        else:
            log(f"❌ Erro na requisição: {response.status_code}")
            log(f"Resposta: {response.content[:200]}")
            return None
            
    except Exception as e:
        log(f"❌ Erro: {e}")
        return None

def load_initial_token():
    """Carrega token do arquivo e obtém a resposta"""
    global CACHED_RESPONSE, CURRENT_TOKEN
    
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
    
    CACHED_RESPONSE = fetch_major_login_response(token)
    return CACHED_RESPONSE is not None

# ============ ROTA CHANGE_TOKEN ============
@app.route('/change_token', methods=['GET'])
def change_token():
    """Muda o token e recarrega a resposta"""
    global CACHED_RESPONSE, CURRENT_TOKEN
    
    access_token = request.args.get('access_token')
    
    if not access_token:
        return jsonify({
            "success": False,
            "error": "Missing access_token parameter"
        }), 400
    
    log("="*50)
    log("🔄 ALTERANDO TOKEN...")
    
    response_data = fetch_major_login_response(access_token)
    
    if response_data:
        CACHED_RESPONSE = response_data
        CURRENT_TOKEN = access_token
        
        # Salva token no arquivo
        with open(TOKEN_FILE, 'w') as f:
            f.write(access_token)
        
        return jsonify({
            "success": True,
            "message": "Token alterado com sucesso!",
            "response_size": len(response_data),
            "account_id": CACHED_DATA.get("account_id"),
            "uid": CACHED_DATA.get("uid"),
            "region": CACHED_DATA.get("region"),
            "token": access_token[:30] + "..."
        })
    else:
        return jsonify({
            "success": False,
            "error": "Falha ao obter resposta para o novo token"
        }), 500

# ============ ROTA MAJORLOGIN ============
@app.route('/MajorLogin', methods=['POST'])
def major_login():
    global CACHED_RESPONSE
    
    if not CACHED_RESPONSE:
        log("❌ Resposta não carregada!")
        return Response("Proxy not initialized", status=500)
    
    try:
        log(f"📥 MajorLogin recebido - retornando resposta clonada")
        log(f"📏 Tamanho da resposta: {len(CACHED_RESPONSE)} bytes")
        
        # Retorna a resposta clonada
        resp = Response(CACHED_RESPONSE, status=200)
        resp.headers["Content-Type"] = "application/octet-stream"
        return resp
            
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
        "response_loaded": CACHED_RESPONSE is not None,
        "response_size": len(CACHED_RESPONSE) if CACHED_RESPONSE else 0,
        "account_id": CACHED_DATA.get("account_id"),
        "jwt_account_id": CACHED_DATA.get("jwt_account_id"),
        "uid": CACHED_DATA.get("uid"),
        "region": CACHED_DATA.get("region"),
        "current_token": CURRENT_TOKEN[:30] + "..." if CURRENT_TOKEN else None,
        "client_version": CLIENT_VERSION,
        "freefire_api": FREEFIRE_API
    })

# ============ INICIALIZACAO ============
if __name__ == '__main__':
    print("\n" + "="*60)
    print("PROXY - MAJORLOGIN CLONE RESPONDER")
    print("="*60)
    
    if load_initial_token():
        print("\n✅ Proxy pronto!")
        print(f"📡 Rodando em http://0.0.0.0:{PORT}")
        print(f"🔀 Rotas:")
        print(f"   /change_token?access_token=TOKEN -> Troca o token e recarrega o clone")
        print(f"   /MajorLogin -> Retorna o clone salvo (NÃO faz requisição)")
        print(f"   /* -> Encaminha para {FREEFIRE_API}")
        print(f"   /status -> Status do proxy")
        print("="*60 + "\n")
        app.run(host='0.0.0.0', port=PORT, debug=False)
    else:
        print("\n❌ Falha na inicialização!")
        print(f"Verifique se o arquivo {TOKEN_FILE} existe e contém um Access Token válido.")
